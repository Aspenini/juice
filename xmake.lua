-- JUICE Uses Instruction Conversion Efficiently
-- ARM64 -> x86-64 dynamic binary translator.
--
--   xmake                       build juice.exe (clang-cl by default)
--   xmake f --toolchain=msvc    build with cl.exe instead
--   xmake test                  build and run all tests

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

-- ---------------------------------------------------------------------------
-- juice-core: portable ARM64 front end + IR (no OS dependencies)
-- ---------------------------------------------------------------------------
target("juice-core")
    set_kind("static")
    add_files("src/core/arm64/**.cpp", "src/core/ir/*.cpp")
    add_includedirs("src", {public = true})
    add_headerfiles("src/core/arm64/**.hpp", "src/core/ir/*.hpp")

-- ---------------------------------------------------------------------------
-- juice-jit: x86-64 code generator (portable across x86-64 operating systems)
-- ---------------------------------------------------------------------------
target("juice-jit")
    set_kind("static")
    add_deps("juice-core")
    add_files("src/core/jit/x64/*.cpp")
    add_headerfiles("src/core/jit/x64/*.hpp")

-- ---------------------------------------------------------------------------
-- juice-runtime: block cache, executable memory, dispatcher
-- ---------------------------------------------------------------------------
target("juice-runtime")
    set_kind("static")
    add_deps("juice-jit")
    add_files("src/runtime/**.cpp")
    add_headerfiles("src/runtime/**.hpp")

-- ---------------------------------------------------------------------------
-- Windows compatibility layer
-- ---------------------------------------------------------------------------
if is_plat("windows") then
    target("juice-pe")
        set_kind("static")
        add_deps("juice-core")
        add_files("src/windows/pe/*.cpp")
        add_headerfiles("src/windows/pe/*.hpp")

    target("juice-win")
        set_kind("static")
        add_deps("juice-pe", "juice-runtime")
        add_files("src/windows/thunk/*.cpp",
                  "src/windows/imports/*.cpp",
                  "src/windows/exceptions/*.cpp",
                  "src/windows/dlls/*.cpp",
                  "src/windows/guest_process.cpp")
        add_headerfiles("src/windows/**.hpp")

    target("juice")
        set_kind("binary")
        add_deps("juice-win")
        add_files("src/main.cpp")
end

includes("tests")
