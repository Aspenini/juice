# JUICE

**JUICE Uses Instruction Conversion Efficiently** — a portable ARM64 → x86-64 dynamic binary
translator. Its core, **libjuice**, is a library with no operating-system dependencies beyond
executable memory. Two front ends sit on top of it:

* **Windows**: runs Windows ARM64 `.exe` programs on x86-64 Windows without a virtual machine,
  forwarding Windows API calls to the native x64 DLLs.
* **Linux** (new, untested): runs Linux AArch64 ELF programs on x86-64 Linux, statically or
  dynamically linked, forwarding system calls to the host kernel, optionally registered with
  `binfmt_misc`.

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
* **DLLs**: the program's own ARM64 DLLs, imported or loaded with `LoadLibrary`, with
  `DllMain`, exports (by name, by ordinal and forwarded), thread-local data and the module
  functions. JUICE also loads the ARM64 C++ runtime DLLs (`vcruntime140`, `msvcp140`) as guest
  code when it can find them.
* **Exceptions**: structured exception handling (`__try`/`__except`/`__finally`,
  `RaiseException`, vectored handlers) and C++ exceptions, with the static and dynamic CRT.
  C++ exceptions with the dynamic CRT need the ARM64 C++ runtime DLLs.
* **Real programs**: the ARM64 tools of the Windows SDK, run on real inputs, produce the same
  output and files as their x64 builds. These include `rc`, `mc`, `midl`, `mt`, `signtool`,
  `makepri`, `winmdidl`, `fxc`, and `dxc`, a large LLVM-based compiler. ARM64 programs can start
  other ARM64 programs.
* Every test program is checked against a natively compiled x86-64 build of the same source.
  Each one runs under the optimizing JIT, the unoptimized JIT and the reference IR interpreter.

```console
> juice hello.exe
Hello, World!
```

The Linux front end is written but has **not yet been compiled or run on Linux**. Its portable
parts (ELF parsing, the initial stack, structure and flag translation, signal frames, the
`binfmt_misc` rule) are unit-tested on every platform, and the rest has only been syntax-checked.
See [Linux layer](#linux-layer).

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

On Linux, the same `xmake` builds `build/linux/x86_64/releasedbg/juice` with GCC or Clang (C++23).
The Linux guest tests need an AArch64 cross compiler (`aarch64-linux-gnu-gcc`/`g++`, e.g. Debian's
`gcc-aarch64-linux-gnu` and `g++-aarch64-linux-gnu`), whose C library also serves the dynamically
linked tests.

To use the translator from another project, link the `libjuice` target and include
`<juice/juice.hpp>`. It documents the `Environment` interface a front end implements.

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
  --dll-path=DIR   also look for the program's ARM64 DLLs in DIR (repeatable)
  --no-vs-runtime  don't use Visual Studio's ARM64 C++ runtime DLLs
  --no-host        don't start a host process for the program's manifest settings
```

`--scan` statically decodes a program's code sections. It shows how close the program is to
running before you try it.

On Linux:

```text
juice [options] [--] program [arguments...]

  --sysroot=DIR       root of the AArch64 system the program expects (its ld.so, libraries,
                      configuration); default JUICE_SYSROOT or QEMU_LD_PREFIX, else wherever
                      the program's ld.so is found (the host, /usr/aarch64-linux-gnu, ...)
  --argv0=NAME        argv[0] for the program
  --strace            log every system call
  --trace, --dump-ir, --stats, --interp, --no-opt, --block-size=N   as on Windows
  --install-binfmt    register with binfmt_misc so AArch64 programs run directly (root)
  --uninstall-binfmt  remove the registration (root)
  --binfmt-config     print the rule for /etc/binfmt.d/juice-aarch64.conf
  --binfmt-status     show the current registration
```

## Architecture

The translator is the portable `libjuice` library. Each operating system is a front end that
implements its `Environment` interface: reading guest code, handling SVC/BRK/undefined-instruction
exits, calls to host code and asynchronous interrupts.

| Library | Directory | Contents |
|---|---|---|
| `libjuice` | `libjuice/include/juice` | Public umbrella header `juice.hpp` |
| | `libjuice/src/core/arm64/state` | Guest CPU state (`CpuState`), laid out as 64-bit slots |
| | `libjuice/src/core/arm64/decode` | Pure decoder (`word, pc → Instruction`) and disassembler |
| | `libjuice/src/core/arm64/lift` | ARM64 → IR lifter, one basic block at a time |
| | `libjuice/src/core/ir` | ISA-neutral SSA IR, optimizer, reference interpreter, shared semantics (`evaluate`) |
| | `libjuice/src/core/jit/x64` | x86-64 assembler and IR → x86-64 code generator (Win64 and SysV ABIs) |
| | `libjuice/src/runtime` | Executable memory, block cache, dispatcher (`Engine`), `Environment` interface |
| `juice-pe` | `src/windows/pe` | PE32+ parser and loader (mapping, relocations, imports, exports, TLS) |
| `juice-win` | `src/windows` | Import binding, API thunks, ABI bridge, callbacks, fault reporting, built-in APIs |
| `juice.exe` | `src/windows/main.cpp` | Windows command line front end |
| `juice-linux-abi` | `src/linux/elf`, `src/linux/abi` | Portable Linux pieces: ELF parser, AArch64 syscall table, x86-64 ⇄ AArch64 structure and flag translation, initial stack, signal frames, `binfmt_misc` rule |
| `juice-linux` | `src/linux` | Linux process: loader, system calls, threads, signals, `binfmt_misc` installation |
| `juice` | `src/linux/main.cpp` | Linux command line front end |

### Translation

* **Decoder.** Covers base A64 integer instructions: arithmetic, logic, bitfield, shifts,
  multiply and divide, conditional select and compare, branches, all load/store addressing modes,
  pairs, exclusives, LSE atomics including `CASP`, `DC ZVA`, and system registers. Scalar
  floating point is covered, including fixed-point conversions. So is Advanced SIMD, in vector
  and scalar forms:
  * loads and stores (LD1–LD4/ST1–ST4) and lane moves;
  * integer arithmetic, including saturating, halving and absolute-difference ops;
  * shifts by immediate and by register (rounding, saturating, accumulating, inserting);
  * widening, narrowing and long multiply-accumulate;
  * by-element ops and `TBL`/`TBX`;
  * vector floating point: arithmetic, fused multiply-add, compares, rounding, conversions
    including fixed-point and half precision, and Arm's exact reciprocal and square-root
    estimates.

  What's still missing is the optional extensions (crypto, CRC32, dot product, FP16
  arithmetic, SVE).
* **IR.** Most Advanced SIMD lane operations are a single `VLane` op, whose immediate selects
  the operation. Values are 64-bit; ALU ops have a 32- or 64-bit width with zero-extended results. Guest
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
* **Self-modifying code.** `IC IVAU`, which code generators run after writing code, drops the
  translations of its cache line. The Linux layer also drops translations on `munmap`, `mremap`,
  fixed `mmap` and `mprotect` to executable.
* **Block cache.** Each block is translated once and shared by all threads. Each thread looks
  blocks up through its own direct-mapped table, so dispatch takes no lock; the shared map is
  locked only on a miss. Blocks and code are never freed while the process runs, so no thread
  can execute code that another thread discarded.

### Windows layer

* **Loader.** Maps the image read/write but *not executable*, applies relocations and parses
  imports, exports and TLS. X18 points to the TEB and implicit TLS gets its own slot.
* **DLLs.** For each DLL the program imports or loads, JUICE first looks for an ARM64 copy, in
  this order:
  1. the program's directory;
  2. any `--dll-path` directories;
  3. the directories in `JUICE_DLL_PATH`;
  4. the ARM64 C++ runtime of an installed Visual Studio (`VC\Redist\MSVC\...\arm64`).

  A DLL found there becomes a guest module, as the native loader would set it up:
  * relocation and import binding, including forwarded exports;
  * implicit TLS, also for threads that already exist when it loads;
  * TLS callbacks and `DllMain` notifications, called in dependency order, with
    `DLL_PROCESS_DETACH` at exit.

  Any other DLL is the native x64 one. With the ARM64 `vcruntime140` and `msvcp140`, C++
  exceptions of programs built with `/MD` are handled entirely in guest code. Guest modules are
  never unmapped (`FreeLibrary` keeps them), so translated code stays valid.
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
  reports), `requestedExecutionLevel` and a few rarer ones. For a program that declares any of
  these, `juice` re-runs
  itself in a copy of `juice.exe` whose own manifest carries them, then waits for it and returns
  its exit code. The two processes share the console and standard handles. Copies are cached per
  manifest in `%LOCALAPPDATA%\juice\hosts` and replaced when `juice.exe` is rebuilt. This adds
  about 10 ms per run. `--no-host` turns it off. A program that asks for administrator rights
  (`requireAdministrator`, or `highestAvailable` for an administrator) gets the UAC prompt.
  It then runs in a new console window, since an elevated process can't share an unelevated
  console. `juice` still waits for it and returns its exit code.
* **Native code pointers.** When the guest jumps to executable code of a native module that it
  never imported, such as a method in the vtable of a COM object created by a system DLL, the
  engine records that address as host code and calls it through the same bridge, returning to
  the guest's link register.
* **Callbacks.** Guest code is mapped non-executable, so a native call into a guest function
  raises an execute fault. A vectored exception handler turns it into a translated guest call
  (x64 → ARM64 arguments) and resumes the native caller with the result.
* **Threads.** Every host thread that runs guest code gets its own guest context: CPU state,
  guest stack, TEB in X18 and its own implicit-TLS vector. Guest TLS callbacks
  get `DLL_THREAD_ATTACH`/`DETACH`. `CreateThread` starts a host thread that runs the guest
  routine. Threads created natively (the thread pool, the native UCRT's `_beginthreadex`) get a
  context the first time they call into guest code. Contexts are freed only once their host
  thread has terminated, because guest code can still run during thread exit.
* **Implicit TLS.** Compiled code finds its thread-local data through the TEB's
  `ThreadLocalStoragePointer`, and executables often assume slot 0 without reading
  `_tls_index`. The translator turns that load (`ldr Xt, [x18, #0x58]`) into a read of a
  per-thread vector of JUICE's own. The program gets slot 0 there and its DLLs the following
  ones, and ntdll's vector (which belongs to the native modules, `juice.exe` included) is never
  touched.
* **Child processes.** When a guest starts an ARM64 program, `CreateProcess` starts `juice.exe`
  on it with the same JUICE settings. The child keeps `argv[0]` as the parent wrote it, and the
  parent gets the juice process, whose exit code is the program's.
* **Loader details.** The loader also sets up the `/GS` security cookie in the image's load
  configuration (Windows' own binaries fail fast if it has its default value).
* **Built-ins.** These replace APIs that must know about the guest:
  * module functions: `GetModuleHandle*`, `GetModuleFileName*`, `GetProcAddress` (which
    thunks native exports on the fly) and `LoadLibrary*`;
  * process information: `GetCommandLine*`, `GetSystemInfo` (reports ARM64),
    `IsProcessorFeaturePresent`, `RtlCaptureContext` (fills an ARM64 `CONTEXT`), `CreateProcess*`
    and the process-exit functions;
  * the resource functions whose NULL module means "the executable": `LoadString`,
    `FindResource`, `FormatMessage`, and so on.

  The process command line is rewritten in place, so native code such as the UCRT's `argv`
  parsing sees the guest's command line. Programs that use the system `msvcrt.dll` get their
  exception handling, RTTI and `setjmp`/`longjmp` from the ARM64 `vcruntime140.dll`, because
  `msvcrt`'s are x64 code.
* **Exceptions.** JUICE has its own ARM64 versions of ntdll's dispatcher and unwinder. They
  walk guest frames using the image's `.pdata`/`.xdata` unwind information, in both packed and
  full form. They call the program's language handlers the way ntdll does, which covers
  `__C_specific_handler` and the C++ runtime's `__CxxFrameHandler4`. They also run termination
  handlers during unwinding and perform the unwind consolidation that executes C++ catch blocks.
  `RaiseException`, `RtlUnwindEx`, `RtlLookupFunctionEntry`, `RtlVirtualUnwind`,
  `RtlRestoreContext`, vectored handlers and the unhandled-exception filter are built-ins. So is
  `vcruntime140`'s `__C_specific_handler`. The exception record and context live on the guest
  stack, as they would natively. To continue at a handler, the dispatcher also unwinds JUICE's
  own nested runs of guest code, using a C++ exception that the run owning the target frame
  catches.
* **Diagnostics.** Guest crashes, unsupported instructions, `__fastfail` and unimplemented
  APIs are reported with the guest register state. Crashes inside JUICE itself print a host
  stack trace as `module+offset` (for `llvm-symbolizer --obj=juice.exe`).

### Linux layer

This layer is written against the kernel ABI but has **not yet been compiled or run on Linux**
(see the status above).

* **Loading.** `juice` maps the AArch64 program's `PT_LOAD` segments readable but never executable
  on the host. A fixed-address program goes at its addresses; a PIE goes wherever the kernel
  places it. For a dynamically linked program, `juice` maps the program's own interpreter
  (`ld-linux-aarch64.so.1` or musl's) and starts there, so the guest's dynamic linker loads its
  libraries. The interpreter is looked up under `--sysroot`, then on the host (multiarch
  installs), then in the usual cross-toolchain roots. The directory it was found in becomes the
  sysroot for the guest's other absolute-path lookups.
* **Process image.** The guest stack follows `RLIMIT_STACK` and has the Linux initial stack layout:
  `argc`, `argv`, `envp` and an auxiliary vector with `AT_PHDR`, `AT_BASE`, `AT_ENTRY`,
  `AT_RANDOM`, and `AT_HWCAP` set to FP, ASIMD and atomics. `brk` is emulated in a region
  reserved after the program.
* **System calls.** Guest and host share the address space, so most AArch64 system calls go
  straight to the host kernel under their x86-64 numbers. The exceptions:
  * calls whose structures differ: `fstat`/`newfstatat` (`struct stat` is 128 bytes on AArch64,
    144 on x86-64) and `epoll_ctl`/`epoll_pwait` (x86-64 packs `epoll_event`);
  * flags with other values: `O_DIRECTORY`, `O_NOFOLLOW`, `O_DIRECT` and `O_LARGEFILE` in
    `openat`, `fcntl` and `pipe2`;
  * emulated state:
    * `brk`;
    * `clone`: threads become host threads, and `fork` forks the emulator;
    * `set_tid_address`/`exit`, for `CLONE_CHILD_CLEARTID` futex wakeups;
    * `rt_sig*` and `sigaltstack`;
    * `uname`, which reports `aarch64`;
    * `/proc/self/exe`;
  * `execve` of an AArch64 program, or of a script whose interpreter is one, starts a new
    `juice` with the same options; other programs are executed natively;
  * calls that would reach the emulator itself are refused, and the C library falls back:
    `rseq`, `seccomp`, `ptrace`, `io_uring`, `clone3` and `openat2`.
* **Signals.** Handlers stay in JUICE. The host handler records the signal, and the dispatcher
  delivers it between blocks: it pushes a genuine AArch64 `rt_sigframe` (siginfo, `ucontext`,
  FP/SIMD record) and runs the guest handler, which returns through `rt_sigreturn`. Implemented:
  * masks and default actions;
  * `SA_RESTART`, `SA_ONSTACK`, `SA_RESETHAND` and `SA_NODEFER`;
  * the temporary masks of `sigsuspend`, `ppoll` and `pselect`;
  * the C library's internal signals 32 and 33.

  `BRK` and undefined instructions raise `SIGTRAP`/`SIGILL` for the guest's handlers.
* **binfmt_misc.** `juice --install-binfmt` registers a rule with flags `P` and `F` that matches
  AArch64 ELF executables, using the same magic and mask as `qemu-aarch64`. The interpreter is a
  `juice-binfmt` symlink next to `juice`. Started under that name, juice reads its arguments the
  way the kernel passes them, and takes its options from the environment (`JUICE_SYSROOT`,
  `JUICE_STRACE=1`, `JUICE_STATS=1`).

## Tests

* `tests/unit`: decoder tests against LLVM-assembled encodings; IR semantics and optimizer tests;
  JIT-vs-interpreter checks of every opcode; end-to-end ARM64 snippets with known results; a
  randomized check that the optimized JIT, unoptimized JIT and interpreter agree on thousands of
  random data-processing instructions; and a stress test that runs one engine on several threads
  at once with exclusive, LSE, 128-bit and CAS increments of shared counters.
* `tests/programs`: freestanding programs (arithmetic, control flow, memory, Win32 API, callbacks,
  threads, GUI, COM, application manifests, auto-vectorized loops, exit codes) built at `-O2` and `-Od`, plus C and C++
  C-runtime programs built `/MT` and `/MD` (threads, SEH, C++ exceptions, a program with DLLs of
  its own). `/MD` programs run with both the ARM64 and the native C++ runtime DLLs.
  Each one is compiled for ARM64 (run under JUICE) and x86-64 (run natively), and the outputs
  must match exactly.
* `tests/linux` (Linux hosts with an AArch64 cross compiler): C and C++ programs that cover
  arguments and the heap, files and epoll, threads, signals, `fork`/`execve` and C++ exceptions.
  Each one is linked statically and dynamically and compared with a native x86-64 build.
* `tests/sdk`: inputs for the Windows SDK tools. If the SDK's ARM64 tools are installed, each
  tool runs as ARM64 under JUICE and as x64 natively, in the same directory. The exit code,
  console output and every file written must match.

## Limitations and roadmap

These are next, roughly in the plan's order:

1. **More ARM64 instructions.** The optional extensions JUICE doesn't report yet: crypto (AES,
   SHA, PMULL 1Q), CRC32, dot product, FP16 arithmetic and LSE128/MOPS. Use `--scan` to see
   what a program needs.
2. **More Win32 APIs.** Signatures for more mixed int/FP functions and by-value structures, and
   structures larger than 16 bytes returned by value through X8.
3. **Windows exceptions.** Software exceptions work. Still missing:
   * Hardware faults in guest code (such as an access violation inside `__try`) are reported
     instead of being delivered to the program.
   * Exceptions can't propagate through native code, for example from a window procedure out
     through `DispatchMessage`. A C++ exception thrown by a native DLL can't be caught by the
     program either, which matters for a `/MD` program without the ARM64 `msvcp140`.
4. **GUI applications.** Plain Win32 GUI programs, COM and manifests work. APIs with by-value
   structures or mixed int/FP arguments (GDI+, Direct2D) need signatures. `uiAccess` in a
   manifest is not honored.
5. **Performance.** Block chaining (direct jumps between translated blocks), register allocation
   instead of spilling every value, inline atomics and SSE instead of helper calls, flag fusion
   for `cmp + b.cond`, and W^X code memory.

Threading caveat: `SuspendThread`/`GetThreadContext` on a guest thread see the host's x64
context, not the guest's ARM64 one.

The Linux front end comes next: compile and run it on a Linux host, then run the guest tests.
Known gaps:
* Hardware faults in guest code (`SIGSEGV`, `SIGBUS`, `SIGFPE`) are reported instead of being
  delivered to guest handlers.
* There is no vDSO, so time functions make real system calls.
* `/proc/self/maps`, `/proc/self/auxv` and `/proc/cpuinfo` show the host's view.
* A `vfork` child gets a copy of memory instead of sharing it.
* Robust futex lists are recorded but not walked when a thread dies.
