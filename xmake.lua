-- JUICE Uses Instruction Conversion Efficiently
-- ARM64 -> x86-64 dynamic binary translator: libjuice plus Windows and Linux frontends.
--
--   xmake                       build juice (Windows: juice.exe with clang-cl by default)
--   xmake f --toolchain=msvc    build with cl.exe instead (Windows)
--   xmake test                  build and run all tests
--   xmake install -o DIR        install juice, libjuice and its headers

set_project("juice")
set_version("0.1.0")
set_xmakever("2.9.0")

add_rules("mode.release", "mode.releasedbg", "mode.debug")
set_defaultmode("releasedbg")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})

set_languages("c++23")

-- Build for native Windows even from MSYS/Git Bash shells (which xmake would treat as mingw).
if is_host("windows") then
    set_defaultplat("windows")
end

if is_plat("windows") then
    if not has_config("toolchain") then
        set_toolchains("clang-cl")
    end
    -- Link the C runtime statically: guest programs built with /MD load the
    -- native ucrtbase.dll, and JUICE must not share its C runtime state with them.
    set_runtimes(is_mode("debug") and "MTd" or "MT")
    add_defines("_CRT_SECURE_NO_WARNINGS", "NOMINMAX", "WIN32_LEAN_AND_MEAN")
end

add_cxxflags("/W4", "/permissive-", "/utf-8", "/EHsc", {tools = {"cl", "clang_cl"}})
-- clang-cl: these warnings are noise for low-level bit-twiddling code.
add_cxxflags("-Wno-sign-compare", "-Wno-missing-field-initializers", {tools = "clang_cl"})
add_cxxflags("-Wall", "-Wextra", {tools = {"gcc", "clang"}})
-- CMPXCHG16B for 128-bit guest atomics (present on every x86-64 CPU that runs 64-bit Windows 8.1+).
add_cxxflags("/clang:-mcx16", {tools = "clang_cl"})
add_cxxflags("-mcx16", {tools = {"gcc", "clang"}})

-- ---------------------------------------------------------------------------
-- libjuice: the portable translator library
--
-- ARM64 decoder and lifter, IR and optimizer, reference interpreter, x86-64
-- code generator, block cache and dispatcher. No operating system code beyond
-- allocating executable memory: frontends supply the guest program and its
-- system (runtime::Environment). Public header: <juice/juice.hpp>.
-- ---------------------------------------------------------------------------
target("libjuice")
    set_kind("static")
    set_basename(is_plat("windows") and "libjuice" or "juice")  -- libjuice.lib / libjuice.a
    add_files("libjuice/src/core/**.cpp", "libjuice/src/runtime/**.cpp")
    add_includedirs("libjuice/src", "libjuice/include", {public = true})
    add_headerfiles("libjuice/include/(juice/*.hpp)")
    add_headerfiles("libjuice/src/(core/**.hpp)", "libjuice/src/(runtime/**.hpp)", {prefixdir = "juice"})
    if not is_plat("windows") then
        add_syslinks("pthread", {public = true})
    end

-- ---------------------------------------------------------------------------
-- Linux ELF/ABI support that does not need Linux itself (ELF parsing, the
-- initial stack, structure and flag translation): built everywhere so the
-- unit tests can cover it on any host.
-- ---------------------------------------------------------------------------
target("juice-linux-abi")
    set_kind("static")
    add_deps("libjuice")
    add_files("src/linux/elf/*.cpp", "src/linux/abi/*.cpp")
    add_includedirs("src", {public = true})

-- ---------------------------------------------------------------------------
-- Windows frontend: runs Windows ARM64 .exe programs
-- ---------------------------------------------------------------------------
if is_plat("windows") then
    target("juice-pe")
        set_kind("static")
        add_deps("libjuice")
        add_files("src/windows/pe/*.cpp")
        add_includedirs("src", {public = true})

    target("juice-win")
        set_kind("static")
        add_deps("juice-pe", "libjuice")
        add_files("src/windows/thunk/*.cpp",
                  "src/windows/imports/*.cpp",
                  "src/windows/exceptions/*.cpp",
                  "src/windows/dlls/*.cpp",
                  "src/windows/manifest.cpp",
                  "src/windows/guest_modules.cpp",
                  "src/windows/guest_threads.cpp",
                  "src/windows/host_manifest.cpp",
                  "src/windows/guest_process.cpp")
        add_syslinks("advapi32", {public = true})

    target("juice")
        set_kind("binary")
        add_deps("juice-win")
        add_files("src/windows/main.cpp")

    -- Regenerates src/windows/thunk/*_generated.inc from the Windows SDK headers
    -- (needs LLVM's libclang): xmake build juice-gen-signatures && xmake run juice-gen-signatures
    option("llvm_dir")
        set_default(path.join(os.getenv("ProgramFiles") or "C:/Program Files", "LLVM"))
        set_showmenu(true)
        set_description("LLVM installation with libclang (for juice-gen-signatures)")
    option_end()
    target("juice-gen-signatures")
        set_kind("binary")
        set_default(false)
        add_files("tools/gen_signatures/gen_signatures.cpp")
        add_includedirs(path.join(get_config("llvm_dir") or "", "include"))
        add_linkdirs(path.join(get_config("llvm_dir") or "", "lib"))
        add_links("libclang")
        set_runargs(os.projectdir(), path.join(os.projectdir(), "src", "windows", "thunk"))
        after_build(function (target)
            os.cp(path.join(get_config("llvm_dir"), "bin", "libclang.dll"), target:targetdir())
        end)
end

-- ---------------------------------------------------------------------------
-- Linux frontend: runs Linux ARM64 ELF programs (static and dynamically
-- linked, through the guest's own ld.so), and can register itself with
-- binfmt_misc.
-- ---------------------------------------------------------------------------
if is_plat("linux") then
    target("juice-linux")
        set_kind("static")
        add_deps("juice-linux-abi", "libjuice")
        add_files("src/linux/*.cpp|main.cpp")

    target("juice")
        set_kind("binary")
        add_deps("juice-linux")
        add_files("src/linux/main.cpp")
end

includes("tests")
