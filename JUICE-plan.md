# JUICE

**JUICE — JUICE Uses Instruction Conversion Efficiently**

## Goal

Build **JUICE**, a C++ compatibility runtime that can run **Windows ARM64 `.exe` programs on x86-64 Windows** without a full virtual machine.

The initial product is Windows-only, but the **ARM64 → x86-64 translation core should be portable**. Only the Windows PE loader, Win32 API thunking, Windows exception handling, and related compatibility code should depend on Windows.

```text
Windows ARM64 .exe
        ↓
     PE Loader
        ↓
   ARM64 Decoder
        ↓
    Custom IR
        ↓
   x86-64 JIT
        ↓
 Native x86-64 Code
        ↓
 Win32 API Thunks
        ↓
   x64 Windows
```

## Language and Tooling

- **C++23**
- **CMake**
- **Clang-cl or MSVC**
- Small amounts of x86-64 assembly where needed
- Custom lightweight JIT rather than LLVM initially

## Project Layout

```text
src/
├── core/
│   ├── arm64/
│   │   ├── decode/
│   │   └── state/
│   ├── ir/
│   └── jit/
│       └── x64/
│
├── runtime/
│   ├── cache/
│   └── memory/
│
├── windows/
│   ├── pe/
│   ├── imports/
│   ├── thunk/
│   ├── exceptions/
│   └── dlls/
│
└── main.cpp
```

## Portable Translator Core

The CPU translator should not depend on Win32.

```text
ARM64 machine code
        ↓
 ARM64 instruction decoder
        ↓
      Custom IR
        ↓
 Simple optimizations
        ↓
  x86-64 code emitter
        ↓
 Native x86-64 code
```

This means the same core could later be reused for projects such as:

- Linux ARM64 → Linux x86-64
- ARM64 binary analysis tools
- Other ARM64 compatibility runtimes
- Different executable formats or operating systems

Windows is simply the first platform built around the translator.

## Initial ARM64 Support

Start with enough instructions to run very small programs:

- MOV
- ADD / SUB
- AND / OR / XOR
- CMP
- B / BL / BR / RET
- LDR / STR
- Basic stack operations

Example:

```text
ARM64:
ADD X0, X1, X2

IR:
a = READ_REG X1
b = READ_REG X2
c = ADD a, b
WRITE_REG X0, c
```

The x86-64 backend then converts the IR into native machine code.

Translated blocks should be cached so frequently executed code is only translated once.

## Windows Compatibility Layer

Windows-specific code sits outside the translator core.

Instead of emulating Windows itself, ARM64 Windows API calls are forwarded into native x64 Windows APIs.

```text
ARM64 application
       ↓
CreateFileW(...)
       ↓
Compatibility thunk
       ↓
x64 CreateFileW(...)
       ↓
Windows
```

Initial DLL/API targets:

- `kernel32.dll`
- `ntdll.dll`
- `user32.dll`
- `advapi32.dll`

The thunking layer handles differences between the **Windows ARM64 ABI** and **Windows x64 ABI**.

## First Target

The first useful milestone should be:

> Load a simple Windows ARM64 console executable, translate its ARM64 code into x86-64, forward the required Windows API calls, and successfully run a Hello World program.

After that, expand into:

1. More ARM64 instructions
2. More Win32 APIs
3. DLL loading
4. Threads
5. Windows exceptions
6. GUI applications
7. More complex ARM64 software

## Project Identity

**Name:** JUICE  
**Expansion:** JUICE Uses Instruction Conversion Efficiently  
**Description:** Portable ARM64 → x86-64 dynamic binary translator with an initial Windows ARM64 compatibility layer.

Suggested component names:

```text
juice/
├── juice-core/      # Portable ARM64 → x86-64 translator
├── juice-jit/       # x86-64 code generator
├── juice-win/       # Windows ARM64 compatibility layer
├── juice-pe/        # Windows PE loader
└── juice.exe
```

## Overall Design

The project is essentially:

**Portable ARM64 → x86-64 dynamic binary translation + a Windows ARM64 compatibility layer.**

The Windows runtime is platform-specific, but the translator itself should remain cleanly separated and portable.
