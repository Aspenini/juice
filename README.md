# JUICE

**JUICE Uses Instruction Conversion Efficiently** — a portable ARM64 → x86-64 dynamic binary
translator with a Windows ARM64 compatibility layer. JUICE runs Windows ARM64 `.exe` programs on
x86-64 Windows without a virtual machine. It translates ARM64 code to x86-64 on demand and forwards
Windows API calls to the native x64 DLLs.

```text
Windows ARM64 .exe ─► PE loader ─► ARM64 decoder ─► IR ─► optimizer ─► x86-64 JIT ─► block cache
                                                                                         │
                     x64 Windows ◄─ native x64 DLLs ◄─ API thunks (ARM64 ⇄ x64 ABI) ◄──────┘
```

## Status

JUICE runs the first milestone (an ARM64 console Hello World) and a good deal more:

* Freestanding programs and programs built with the **static (`/MT`)** and **dynamic (`/MD`)**
  Microsoft C runtime, in both C and C++. Covers `printf` with floating point, math, strings,
  `qsort`, heap, thread-local storage, global constructors and destructors, `atexit`, virtual
  calls and STL containers.
* Windows API calls to `kernel32`, `ntdll`, `user32`, `advapi32`, the UCRT and anything else that
  exists as an x64 DLL.
* **Callbacks** from native code into the program (window procedures, `qsort` comparators,
  `InitOnceExecuteOnce`, FLS destructors, CRT `_initterm`/`atexit` tables).
* **Win32 GUI and COM**: window classes and procedures, controls, dialogs, resources, GDI, and COM
  objects used in both directions (calling system objects through their vtables, and system DLLs
  calling objects the program implements). The program's manifest applies: visual styles (common
  controls v6), DPI awareness, the UTF-8 code page, long paths, the segment heap and supported
  OS versions.
* **Threads**: `CreateThread`, `std::thread` (static and dynamic CRT), thread-pool callbacks,
  `thread_local` objects with constructors and destructors, and guest atomics that are really
  atomic across threads.
* Every test program is checked against a natively compiled x86-64 build of the same source.
  Each one runs under the optimizing JIT, the unoptimized JIT and the reference IR interpreter.

```console
> juice hello.exe
Hello, World!
```

## Building

Requirements: [xmake](https://xmake.io) ≥ 2.9 and clang-cl or MSVC (C++23). The tests also need
clang-cl and the ARM64 Windows SDK libraries to build ARM64 test programs. The C runtime tests also
need an MSVC toolset that ships the ARM64 CRT, such as the VS 2022 "MSVC ARM64 build tools"
component. xmake finds it automatically; override with `xmake f --guest_vctoolsdir=<VC/Tools/MSVC/version>`.

```bash
xmake          # build juice.exe (clang-cl, release with debug info)
xmake test     # build and run the unit and guest-program tests
```

`juice.exe` ends up in `build/windows/x64/releasedbg/`. To build with `cl.exe` instead of clang-cl,
run `xmake f --toolchain=msvc`; for a debug build, run `xmake f -m debug`. `xmake test -v` shows
the output of failing tests, and `xmake test "juice-guest-tests/crt_*"` runs a subset.
`build/compile_commands.json` is kept up to date for editors.

## Usage

```text
juice [options] program.exe [arguments...]

  --trace          log every translated block with its disassembly
  --dump-ir        log the IR of every translated block
  --trace-calls    log every Windows API call (and callback) made by the program
  --trace-imports  log how each import was resolved
  --stats          print translation statistics, hot blocks and API call counts at exit
  --interp         execute IR with the reference interpreter instead of the JIT
  --no-opt         disable IR optimizations
  --block-size=N   maximum guest instructions per translated block (default 64)
  --scan           don't run; list instructions in the program JUICE cannot translate
  --no-host        don't start a host process for the program's manifest settings
```

`--scan` statically decodes a program's code sections. It shows how close the program is to
running before you try it.

## Architecture

The translator core does not depend on Windows. Only the PE loader, API thunks, exception handling
and API built-ins do.

| Library | Directory | Contents |
|---|---|---|
| `juice-core` | `src/core/arm64/state` | Guest CPU state (`CpuState`), laid out as 64-bit slots |
| | `src/core/arm64/decode` | Pure decoder (`word, pc → Instruction`) and disassembler |
| | `src/core/arm64/lift` | ARM64 → IR lifter, one basic block at a time |
| | `src/core/ir` | ISA-neutral SSA IR, optimizer, reference interpreter, shared semantics (`evaluate`) |
| `juice-jit` | `src/core/jit/x64` | x86-64 assembler and IR → x86-64 code generator (Win64 and SysV) |
| `juice-runtime` | `src/runtime` | Executable memory, block cache, dispatcher (`Engine`), `Environment` interface |
| `juice-pe` | `src/windows/pe` | PE32+ parser and loader (mapping, relocations, imports, exports, TLS) |
| `juice-win` | `src/windows` | Import binding, API thunks, ABI bridge, callbacks, fault reporting, built-in APIs |
| `juice.exe` | `src/main.cpp` | Command line front end |

### Translation

* **Decoder.** Covers base A64 integer instructions: arithmetic, logic, bitfield, shifts,
  multiply and divide, conditional select and compare, branches, all load/store addressing modes,
  pairs, exclusives and LSE atomics, and system registers. It also covers the scalar FP and
  Advanced SIMD subset that compilers and the CRT emit: LD1–LD4/ST1–ST4, lane moves,
  compares, pairwise and across-lane ops, shifts, narrow/widen, permutes, and FP arithmetic,
  FMA, conversions, rounding and compares.
* **IR.** Values are 64-bit; ALU ops have a 32- or 64-bit width with zero-extended results. Guest
  state is addressed as slots and guest memory through host pointers, since guest and host share
  the address space. Flags are a packed NZCV value that the flag-producing ops compute. Vector ops
  work on 64-bit vector halves, and FP ops carry IEEE bit patterns.
* **Optimizer.** Constant folding, algebraic simplification, guest-register read forwarding,
  dead guest-register store elimination and dead value elimination, all within a block.
* **x86-64 backend.** Guest state lives behind RBX and IR values in a scratch array behind RBP. The
  vector and FP ops call back into `ir::evaluate`, so the JIT and the interpreter share one
  definition of their semantics. That code includes ARM NaN propagation, the default NaN and
  saturating conversions.
* **Atomics.** LSE atomics (`CAS`, `SWP`, `LDADD`, ...) become single atomic host operations.
  Exclusives are emulated by value: `LDXR`/`LDXP` record the loaded value, and `STXR`/`STXP` store
  with a compare-and-swap against it (`CMPXCHG16B` for 128-bit pairs), failing if memory changed.
  Like other translators, this accepts an A-B-A change as unchanged. `STLR` is a locked store, and
  full `DMB`/`DSB` barriers become `MFENCE`. x86-64's stronger ordering covers the other variants.
* **Block cache.** Each block is translated once and shared by all threads. Each thread looks
  blocks up through its own direct-mapped table, so dispatch takes no lock; the shared map is
  locked only on a miss. Blocks and code are never freed while the process runs, so no thread
  can execute code that another thread discarded.

### Windows layer

* **Loader.** Maps the image read/write but *not executable*, applies relocations and parses
  imports, exports and TLS. X18 points to the TEB and implicit TLS gets its own slot.
* **API calls.** Each import becomes a unique address in a reserved, inaccessible region. When the
  dispatcher reaches one, it calls the native function. A generated x64 trampoline converts the
  ARM64 calling convention to x64, passing X0–X7, D0–D3 and stack arguments. It returns both RAX
  and XMM0, so integer and FP results both work. Variadic functions work too, because Windows
  ARM64 passes variadic floats in integer registers. A small signature table covers the
  functions the generic rules get wrong. These are UCRT functions that mix int and FP arguments
  (`ldexp`, `frexp`, ...), and 16-byte structures passed or returned by value (`_Thrd_join`,
  `lldiv`), which ARM64 puts in two registers and x64 passes by pointer.
* **Manifest.** The program's embedded application manifest becomes the process default
  activation context before its imports are bound. This applies side-by-side redirection, such as
  common controls v6 and visual styles, to its imports, the controls it creates and DLLs it
  loads later. The declared DPI awareness (`dpiAwareness`, `dpiAware`, `gdiScaling`) is applied
  with `SetProcessDpiAwarenessContext`.
* **Process-creation settings.** Windows applies some manifest settings only when it creates a
  process: `activeCodePage` (UTF-8), `longPathAware`, `heapType` (segment heap), the
  `supportedOS`/`maxversiontested` compatibility entries (for example, what `GetVersionEx`
  reports) and a few rarer ones. For a program that declares any of these, `juice` re-runs
  itself in a copy of `juice.exe` whose own manifest carries them, then waits for it and returns
  its exit code. The two processes share the console and standard handles. Copies are cached per
  manifest in `%LOCALAPPDATA%\juice\hosts` and replaced when `juice.exe` is rebuilt. This adds
  about 10 ms per run. `--no-host` turns it off.
* **Native code pointers.** When the guest jumps to executable code of a native module that it
  never imported, such as a method in the vtable of a COM object created by a system DLL, the
  engine records that address as host code and calls it through the same bridge, returning to
  the guest's link register.
* **Callbacks.** Guest code is mapped non-executable, so a native call into a guest function
  raises an execute fault. A vectored exception handler turns it into a translated guest call
  (x64 → ARM64 arguments) and resumes the native caller with the result.
* **Threads.** Every host thread that runs guest code gets its own guest context: CPU state,
  guest stack, TEB in X18 and a slot in the thread's implicit-TLS vector. Guest TLS callbacks
  get `DLL_THREAD_ATTACH`/`DETACH`. `CreateThread` starts a host thread that runs the guest
  routine. Threads created natively (the thread pool, the native UCRT's `_beginthreadex`) get a
  context the first time they call into guest code. Contexts are freed only once their host
  thread has terminated, because guest code can still run during thread exit.
* **Built-ins.** These replace APIs that must know about the guest: `GetModuleHandle*`,
  `GetModuleFileName*`, `GetProcAddress` (which thunks native exports on the fly),
  `GetCommandLine*`, `GetSystemInfo` (reports ARM64), `IsProcessorFeaturePresent`,
  `RtlCaptureContext` (fills an ARM64 `CONTEXT`) and the process-exit functions. The process
  command line is rewritten in place, so native code such as the UCRT's `argv` parsing sees the
  guest's command line.
* **Diagnostics.** Guest crashes, unsupported instructions, `__fastfail` and unimplemented
  APIs are reported with the guest register state. Crashes inside JUICE itself print a host
  stack trace as `module+offset` (for `llvm-symbolizer --obj=juice.exe`).

## Tests

* `tests/unit`: decoder tests against LLVM-assembled encodings; IR semantics and optimizer tests;
  JIT-vs-interpreter checks of every opcode; end-to-end ARM64 snippets with known results; a
  randomized check that the optimized JIT, unoptimized JIT and interpreter agree on thousands of
  random data-processing instructions; and a stress test that runs one engine on several threads
  at once with exclusive, LSE, 128-bit and CAS increments of shared counters.
* `tests/programs`: freestanding programs (arithmetic, control flow, memory, Win32 API, callbacks,
  threads, GUI, COM, application manifests, exit codes) built at `-O2` and `-Od`, plus C and C++ C-runtime programs built `/MT`
  and `/MD`.
  Each one is compiled for ARM64 (run under JUICE) and x86-64 (run natively), and the outputs
  must match exactly.

## Limitations and roadmap

These are next, roughly in the plan's order:

1. **More ARM64 instructions.** The remaining Advanced SIMD (vector FP, TBL, saturating and
   widening arithmetic), CRC32, crypto, `CASP`, and LSE128/MOPS. Use `--scan` to see what a
   program needs.
2. **More Win32 APIs.** Signatures for more mixed int/FP functions and by-value structures, and
   structures larger than 16 bytes returned by value through X8.
3. **DLL loading.** Load ARM64 DLLs as guest modules (`LoadLibrary`, imports between guest DLLs).
4. **Windows exceptions.** Deliver faults to the guest as SEH exceptions and unwind ARM64 frames
   (`.pdata`/`.xdata`). This also enables C++ exceptions.
5. **GUI applications.** Plain Win32 GUI programs, COM and manifests work. APIs with by-value
   structures or mixed int/FP arguments (GDI+, Direct2D) need signatures. A manifest's
   `requestedExecutionLevel` is not honored: programs always run as the invoking user.
6. **Performance.** Block chaining (direct jumps between translated blocks), register allocation
   instead of spilling every value, inline atomics and SSE instead of helper calls, flag fusion
   for `cmp + b.cond`, and W^X code memory.

Threading caveats: if a native DLL with implicit TLS is loaded after start-up, ntdll rebuilds the
TLS vectors and drops the guest's slot. `SuspendThread`/`GetThreadContext` on a guest thread see
the host's x64 context, not the guest's ARM64 one.
