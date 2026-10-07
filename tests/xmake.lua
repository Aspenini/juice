-- ---------------------------------------------------------------------------
-- Unit tests (portable core + runtime)
-- ---------------------------------------------------------------------------
target("juice-unit-tests")
    set_kind("binary")
    set_default(false)
    add_deps("libjuice", "juice-linux-abi")
    add_files("unit/*.cpp")
    add_tests("unit")

-- ---------------------------------------------------------------------------
-- Linux guest program tests
--
-- Each program in linux/ is cross-compiled for AArch64, linked statically and
-- dynamically, and run under juice; a native x86-64 build is the reference
-- for stdout and the exit code. Needs an AArch64 cross toolchain
-- (aarch64-linux-gnu-gcc/g++, e.g. Debian's gcc-aarch64-linux-gnu and
-- g++-aarch64-linux-gnu, which also install the C library juice's
-- dynamic tests load from /usr/aarch64-linux-gnu).
-- ---------------------------------------------------------------------------
if is_plat("linux") then
    target("juice-linux-guest-tests")
        set_kind("phony")
        set_default(false)
        add_deps("juice")
        set_values("linux.programs", "hello.c", "files.c", "threads.c", "signals.c", "exec.c", "cxx.cpp")

        on_load(function (target)
            import("lib.detect.find_program")
            local cross = {c = find_program("aarch64-linux-gnu-gcc"), cxx = find_program("aarch64-linux-gnu-g++")}
            local native = {c = find_program("cc") or find_program("gcc"), cxx = find_program("c++") or find_program("g++")}
            if not cross.c or not native.c then
                print("juice: aarch64-linux-gnu-gcc not found, Linux guest program tests disabled")
                return
            end
            local scriptdir = target:scriptdir()
            local outdir = path.join(target:targetdir(), "linux-guest")
            local jobs = {}
            local special = {
                hello = {args = {"one", "two words"}, env = {JUICE_TEST_VAR = "set"}},
            }
            for _, file in ipairs(target:values("linux.programs")) do
                local name = path.basename(file)
                local lang = path.extension(file) == ".cpp" and "cxx" or "c"
                local src = path.join(scriptdir, "linux", file)
                local flags = {"-O2", "-Wall", "-pthread", lang == "cxx" and "-std=c++17" or "-std=gnu11"}
                local reference = path.join(outdir, name .. ".x86_64")
                table.insert(jobs, {name = name .. " (x86_64)", exe = reference, src = src,
                                    steps = {{native[lang], table.join(flags, {src, "-o", reference})}}})
                if cross[lang] then
                    for _, link in ipairs({"static", "dynamic"}) do
                        local guest = path.join(outdir, name .. "-" .. link .. ".aarch64")
                        local ldflags = link == "static" and {"-static"} or {}
                        table.insert(jobs, {name = name .. " (aarch64, " .. link .. ")", exe = guest, src = src,
                                            steps = {{cross[lang], table.join(flags, ldflags, {src, "-o", guest})}}})
                        local modes = {jit = {}, interp = {"--interp"}, noopt = {"--no-opt", "--block-size=1"}}
                        for mode, mode_flags in pairs(modes) do
                            local test = table.join({guest = guest, reference = reference, flags = mode_flags},
                                                    special[name] or {})
                            target:add("tests", name .. "." .. link .. "." .. mode, test)
                        end
                    end
                end
            end
            target:data_set("linux.jobs", jobs)
            target:data_set("linux.outdir", outdir)
        end)

        on_build(function (target, opt)
            import("core.project.depend")
            import("utils.progress")
            local jobs = target:data("linux.jobs")
            if not jobs then
                return
            end
            os.mkdir(target:data("linux.outdir"))
            for _, job in ipairs(jobs) do
                depend.on_changed(function ()
                    progress.show(opt.progress, "${color.build.object}compiling.guest %s", job.name)
                    for _, step in ipairs(job.steps) do
                        os.vrunv(step[1], step[2])
                    end
                end, {dependfile = job.exe .. ".d", files = {job.src}, lastmtime = os.mtime(job.exe)})
            end
        end)

        on_test(function (target, opt)
            local juice = path.absolute(target:dep("juice"):targetfile())
            local logdir = path.join(target:autogendir(), "tests")
            local logname = opt.name:gsub("[/\\:]", "_")
            os.mkdir(logdir)
            local function run(program, argv, tag)
                local outfile = path.join(logdir, logname .. "." .. tag .. ".out")
                local errfile = path.join(logdir, logname .. "." .. tag .. ".err")
                local code = os.execv(program, argv, {try = true, timeout = 120000, stdout = outfile,
                                                      stderr = errfile, envs = opt.env})
                local out = os.isfile(outfile) and io.readfile(outfile) or ""
                local err = os.isfile(errfile) and io.readfile(errfile) or ""
                os.tryrm(outfile)
                os.tryrm(errfile)
                return code, out, err
            end
            local args = opt.args or {}
            local code, out, err = run(juice, table.join(opt.flags, {"--", opt.guest}, args), "juice")
            local ref_code, ref_out = run(opt.reference, args, "reference")
            if code ~= ref_code then
                opt.errors = string.format("exit code mismatch: juice=%s expected=%s\n%s", tostring(code),
                                           tostring(ref_code), err)
                return false
            end
            if out ~= ref_out then
                opt.errors = "output mismatch\n--- juice ---\n" .. out .. "\n--- expected ---\n" .. ref_out ..
                             "\n--- juice stderr ---\n" .. err
                return false
            end
            return true
        end)
end

if not is_plat("windows") then
    return
end

-- ---------------------------------------------------------------------------
-- Guest program tests
--
-- Each program in programs/ is compiled for ARM64 (run under juice.exe) and
-- for x86-64 (run natively as the reference); the tests compare stdout and
-- exit codes. Building ARM64 programs needs clang-cl plus the ARM64 Windows
-- SDK import libraries. The C runtime programs (/MT and /MD) additionally
-- need an MSVC toolset that ships the ARM64 C runtime libraries; the same
-- toolset builds their x64 reference.
-- ---------------------------------------------------------------------------
option("guest_vctoolsdir")
    set_default("")
    set_showmenu(true)
    set_description("MSVC toolset (VC/Tools/MSVC/<version>) with ARM64 and x64 C runtime libraries",
                    "(auto-detected when empty)")
option_end()

target("juice-guest-tests")
    set_kind("phony")
    set_default(false)
    add_deps("juice")

    -- Freestanding programs: no C runtime, entry point mainCRTStartup.
    set_values("guest.freestanding", "hello", "arith", "control", "memory", "winapi", "callback",
               "exitcode", "retcode", "threads", "gui", "com", "manifest", "settings", "vector")
    -- C runtime programs, built /MT and /MD.
    set_values("guest.crt", "crt_c.c", "crt_cpp.cpp", "crt_threads.cpp", "crt_threadctl.c", "crt_faults.c", "crt_seh.c", "crt_eh.cpp", "crt_crypto.c",
               "crt_simdext.c", "crt_fp16.c", "crt_newops.c",
               "crt_newops2.c", "crt_abi.cpp")

    on_load(function (target)
        import("lib.detect.find_program")

        local cc = find_program("clang-cl", {paths = {path.join(os.getenv("ProgramFiles") or "", "LLVM", "bin")}})
        if not cc then
            print("juice: clang-cl not found, guest program tests disabled")
            return
        end

        local vctools = get_config("guest_vctoolsdir")
        if not vctools or vctools == "" then
            vctools = nil
            local pattern = path.join(os.getenv("ProgramFiles") or "", "Microsoft Visual Studio", "*", "*",
                                      "VC", "Tools", "MSVC", "*", "lib", "arm64", "libcmt.lib")
            for _, lib in ipairs(os.files(pattern)) do
                local dir = path.directory(path.directory(path.directory(lib)))
                if os.isfile(path.join(dir, "lib", "x64", "libcmt.lib")) and
                   os.isfile(path.join(dir, "lib", "arm64", "msvcrt.lib")) then
                    vctools = dir
                end
            end
        end
        if not vctools then
            print("juice: no MSVC toolset with ARM64 C runtime libraries, C runtime tests disabled")
        end

        local scriptdir = target:scriptdir()
        local outdir = path.join(target:targetdir(), "guest")
        local arches = {{"arm64", "aarch64-pc-windows-msvc"}, {"x64", "x86_64-pc-windows-msvc"}}
        local jobs = {}
        local function exe_name(name, variant, arch)
            return path.join(outdir, name .. "-" .. variant .. "." .. arch .. ".exe")
        end
        -- Extra compiler flags for one architecture's build of a program (optional ARM64 extensions).
        local arch_flags = {
            crt_crypto = {arm64 = {"/clang:-march=armv8.2-a+crypto+sha3"}},
            crt_simdext = {arm64 = {"/clang:-march=armv8.6-a+fp16fml"}},
            crt_fp16 = {arm64 = {"/clang:-march=armv8.2-a+fp16"}},
            crt_newops = {arm64 = {"/clang:-march=armv8.9-a+lse128+mops+cssc+rcpc3+wfxt"}},
            crt_newops2 = {arm64 = {"/clang:-march=armv8.9-a+sm4+cmpbr+cpa+lsui+fprcvt+faminmax"}},
            crt_faults = {arm64 = {"/clang:-march=armv8.8-a+mops"}},
        }
        -- The x64 reference of crt_fp16 uses _Float16, whose conversions are compiler-rt builtins.
        local builtins = os.files(path.join(path.directory(path.directory(cc)), "lib", "clang", "*", "lib", "windows",
                                            "clang_rt.builtins-x86_64.lib"))
        local arch_libs = {}
        if #builtins > 0 then
            arch_libs.crt_fp16 = {x64 = {builtins[1]}}
        end
        local abi_libs = {"gdiplus.lib", "d2d1.lib", "dwrite.lib", "windowscodecs.lib", "ole32.lib", "oleaut32.lib"}
        arch_libs.crt_abi = {x64 = abi_libs, arm64 = abi_libs}
        local function add_job(name, variant, src, deps, flags, ldflags)
            for _, a in ipairs(arches) do
                local exe = exe_name(name, variant, a[1])
                local extra = (arch_flags[name] or {})[a[1]] or {}
                local libs = (arch_libs[name] or {})[a[1]]
                local link = ldflags
                if libs then link = table.join(#ldflags > 0 and ldflags or {"/link"}, libs) end
                local argv = table.join({"--target=" .. a[2]}, flags, extra, {"/" .. variant, src,
                                        "/Fo" .. path.join(outdir, name .. "-" .. variant .. "." .. a[1] .. ".obj"),
                                        "/Fe" .. exe}, link)
                table.insert(jobs, {name = name .. " (" .. a[1] .. ", /" .. variant .. ")", exe = exe,
                                    steps = {argv}, files = table.join({src}, deps)})
            end
        end
        local function add_guest_test(name, variant, mode, opt)
            local test = table.join({guest = opt.guest or exe_name(name, variant, "arm64")}, opt)
            if not opt.expect_output then
                test.reference = opt.reference or exe_name(name, variant, "x64")
            end
            local flags = {jit = {}, interp = {"--interp"}, noopt = {"--no-opt", "--block-size=1"},
                           nativert = {"--no-vs-runtime"}}
            test.flags = flags[mode]
            target:add("tests", name .. "." .. variant .. "." .. mode, test)
        end

        -- Freestanding programs at /O2 and /Od.
        local header = path.join(scriptdir, "programs", "juice_test.h")
        local cflags = {"/nologo", "/GS-", "/Zl", "/W3", "/clang:-fno-vectorize", "/clang:-fno-slp-vectorize"}
        local ldflags = {"/link", "/entry:mainCRTStartup", "/nodefaultlib", "/subsystem:console",
                         "kernel32.lib", "user32.lib", "advapi32.lib", "gdi32.lib",
                         "ole32.lib", "shlwapi.lib", "uuid.lib", "comctl32.lib"}
        local special = {
            winapi = {args = {"alpha", "two words"}},
            -- Returning from the entry point: compared with a fixed expectation,
            -- since natively that only ends the main thread.
            retcode = {expect_exit = 7, expect_output = "returning 7\n"},
        }
        -- Programs with an application manifest (programs/<name>.manifest), embedded by the linker.
        local manifests = {manifest = true, settings = true}
        for _, name in ipairs(target:values("guest.freestanding")) do
            local src = path.join(scriptdir, "programs", name .. ".c")
            local deps = {header}
            local link = ldflags
            if manifests[name] then
                local file = path.join(scriptdir, "programs", name .. ".manifest")
                table.insert(deps, file)
                link = table.join(ldflags, {"/manifest:embed", "/manifestuac:no", "/manifestinput:" .. file})
            end
            -- vector.c is built to be auto-vectorized (no FP contraction: x86-64 has no FMA by default).
            local flags = cflags
            if name == "vector" then
                flags = {"/nologo", "/GS-", "/Zl", "/W3", "/clang:-fno-math-errno", "/clang:-ffp-contract=off"}
            end
            for _, opt in ipairs({"O2", "Od"}) do
                add_job(name, opt, src, deps, flags, link)
                for _, mode in ipairs({"jit", "interp", "noopt"}) do
                    add_guest_test(name, opt, mode, special[name] or {})
                end
            end
        end

        -- C runtime programs, /MT and /MD.
        if vctools then
            local crt_cflags = {"/nologo", "/O2", "/W3", "/clang:-ffp-contract=off", "/clang:-fno-vectorize",
                                "/clang:-fno-slp-vectorize", "/vctoolsdir" .. vctools}
            local no_exceptions = {"/EHs-c-", "/D_HAS_EXCEPTIONS=0"}
            local crt_special = {crt_c = {args = {"one", "two words"}}}
            -- C++ exceptions with /MD need the ARM64 C++ runtime DLLs (juice
            -- finds Visual Studio's): vcruntime140.dll's x64 frame handler can't
            -- handle ARM64 frames.
            local cxx_exceptions = {crt_eh = true}
            local runtime_dlls = os.files(path.join(os.getenv("ProgramFiles") or "", "Microsoft Visual Studio", "*",
                                                    "*", "VC", "Redist", "MSVC", "*", "arm64", "Microsoft.VC*.CRT",
                                                    "vcruntime140.dll"))
            local has_arm64_runtime = #runtime_dlls > 0
            if not has_arm64_runtime then
                print("juice: Visual Studio's ARM64 C++ runtime DLLs not found, /MD C++ exception tests disabled")
            end
            for _, file in ipairs(target:values("guest.crt")) do
                local name = path.basename(file)
                local src = path.join(scriptdir, "programs", file)
                local flags = table.join(crt_cflags, cxx_exceptions[name] and {"/EHsc"} or no_exceptions)
                local runtimes = {"MT", "MD"}
                if cxx_exceptions[name] and not has_arm64_runtime then runtimes = {"MT"} end
                for _, rt in ipairs(runtimes) do
                    add_job(name, rt, src, {}, flags, {})
                    local modes = {"jit", "interp"}
                    -- /MD programs also run with the native x64 vcruntime140.dll.
                    if rt == "MD" and has_arm64_runtime and not cxx_exceptions[name] then table.insert(modes, "nativert") end
                    for _, mode in ipairs(modes) do
                        add_guest_test(name, rt, mode, crt_special[name] or {})
                    end
                end
            end

            -- A program with DLLs of its own (programs/dll), each architecture and
            -- runtime in a directory of its own so that the DLLs sit next to the program.
            local dll_src = path.join(scriptdir, "programs", "dll")
            local dll_files = os.files(path.join(dll_src, "*.[ch]"))
            for _, rt in ipairs({"MT", "MD"}) do
                local exes = {}
                for _, a in ipairs(arches) do
                    local dir = path.join(outdir, "crt_dll", a[1] .. "-" .. rt)
                    local function compile(src, out, extra)
                        return table.join({"--target=" .. a[2]}, crt_cflags, no_exceptions, {"/" .. rt, src,
                                          "/Fo" .. path.join(dir, path.basename(src) .. ".obj"), "/Fe" .. out}, extra)
                    end
                    local lib = path.join(dir, "crt_dll_lib")
                    local exe = path.join(dir, "crt_dll.exe")
                    exes[a[1]] = exe
                    local sub = path.join(dir, "sub")
                    local deplib = path.join(sub, "crt_dll_deplib")
                    table.insert(jobs, {name = "crt_dll (" .. a[1] .. ", /" .. rt .. ")", exe = exe, dir = dir,
                                        subdirs = {sub}, files = dll_files, steps = {
                        compile(path.join(dll_src, "crt_dll_lib.c"), lib .. ".dll", {"/LD"}),
                        compile(path.join(dll_src, "crt_dll_plugin.c"), path.join(dir, "crt_dll_plugin.dll"),
                                {"/LD", "/link", lib .. ".lib"}),
                        compile(path.join(dll_src, "crt_dll_deplib.c"), deplib .. ".dll", {"/LD"}),
                        compile(path.join(dll_src, "crt_dll_dep.c"), path.join(sub, "crt_dll_dep.dll"),
                                {"/LD", "/link", deplib .. ".lib"}),
                        compile(path.join(dll_src, "crt_dll_com.c"), path.join(dir, "crt_dll_com.dll"),
                                {"/LD", "/link", "ole32.lib", "uuid.lib"}),
                        compile(path.join(dll_src, "crt_dll.c"), exe, {"/link", lib .. ".lib"})}})
                end
                for _, mode in ipairs({"jit", "interp"}) do
                    add_guest_test("crt_dll", rt, mode, {guest = exes.arm64, reference = exes.x64})
                end
            end
        end

        target:data_set("guest.cc", cc)
        target:data_set("guest.jobs", jobs)
        target:data_set("guest.outdir", outdir)
    end)

    on_build(function (target, opt)
        import("core.project.depend")
        import("async.runjobs")
        import("utils.progress")

        local cc = target:data("guest.cc")
        local jobs = target:data("guest.jobs")
        if not cc or not jobs then
            return
        end
        os.mkdir(target:data("guest.outdir"))
        runjobs("guest_programs", function (index)
            local job = jobs[index]
            if job.dir then os.mkdir(job.dir) end
            for _, dir in ipairs(job.subdirs or {}) do os.mkdir(dir) end
            depend.on_changed(function ()
                progress.show(opt.progress, "${color.build.object}compiling.guest %s", job.name)
                for _, argv in ipairs(job.steps) do
                    os.vrunv(cc, argv)
                end
            end, {dependfile = job.exe .. ".d", files = job.files, values = table.join(table.unpack(job.steps)), lastmtime = os.mtime(job.exe)})
        end, {total = #jobs, comax = os.default_njob()})
    end)

    -- Run the ARM64 program under juice and compare stdout and the exit code
    -- with the native x64 reference (or the fixed expectations).
    on_test(function (target, opt)
        local juice = path.absolute(target:dep("juice"):targetfile())
        local logdir = path.join(target:autogendir(), "tests")
        local logname = opt.name:gsub("[/\\:]", "_")
        os.mkdir(logdir)

        local function run(program, argv, tag)
            local outfile = path.join(logdir, logname .. "." .. tag .. ".out")
            local errfile = path.join(logdir, logname .. "." .. tag .. ".err")
            local code = os.execv(program, argv, {try = true, timeout = 120000, stdout = outfile, stderr = errfile})
            local out = os.isfile(outfile) and io.readfile(outfile) or ""
            local err = os.isfile(errfile) and io.readfile(errfile) or ""
            os.tryrm(outfile)
            os.tryrm(errfile)
            return code, out, err
        end

        local args = opt.args or {}
        local code, out, err = run(juice, table.join(opt.flags, {opt.guest}, args), "juice")
        opt.stdout = out
        opt.stderr = err

        local ref_code, ref_out
        if opt.reference then
            ref_code, ref_out = run(opt.reference, args, "reference")
            -- A reference that crashes (an NTSTATUS error as exit code) proves nothing.
            if ref_code < 0 or ref_code >= 0xC0000000 then
                opt.errors = string.format("the native reference crashed (exit code 0x%x)", ref_code & 0xFFFFFFFF)
                return false
            end
        else
            ref_code, ref_out = opt.expect_exit, opt.expect_output
        end

        if code ~= ref_code then
            opt.errors = string.format("exit code mismatch: juice=%s expected=%s", tostring(code), tostring(ref_code))
            return false
        end
        if out ~= ref_out then
            opt.errors = "output mismatch\n--- juice ---\n" .. out .. "\n--- expected ---\n" .. ref_out
            return false
        end
        return true
    end)

-- ---------------------------------------------------------------------------
-- Windows SDK tool tests
--
-- The Windows SDK ships ARM64 builds of its tools next to the x64 ones. Each
-- test runs a tool both ways on the inputs in sdk/ - the ARM64 build under
-- juice, the x64 build natively - in the same directory (so that printed
-- paths match) and compares the exit code, the console output and every file
-- the tool writes. Run with `xmake test "juice-sdk-tests/*"`.
-- ---------------------------------------------------------------------------
target("juice-sdk-tests")
    set_kind("phony")
    set_default(false)
    add_deps("juice")

    on_load(function (target)
        local kits = path.join(os.getenv("ProgramFiles(x86)") or "", "Windows Kits", "10")
        local bin
        for _, rc in ipairs(os.files(path.join(kits, "bin", "*", "arm64", "rc.exe"))) do
            local dir = path.directory(path.directory(rc))
            if os.isfile(path.join(dir, "x64", "rc.exe")) and (not bin or dir > bin) then bin = dir end
        end
        if not bin then
            print("juice: Windows SDK ARM64 tools not found, SDK tool tests disabled")
            return
        end
        local version = path.filename(bin)
        local include = path.join(kits, "Include", version)
        local envs = {INCLUDE = path.join(include, "um") .. ";" .. path.join(include, "shared")}
        local inputs = path.join(target:scriptdir(), "sdk")
        local winmd = os.files(path.join(kits, "References", version, "Windows.Foundation.FoundationContract", "*",
                                         "Windows.Foundation.FoundationContract.winmd"))[1]

        local tests = {
            rc = {"rc", {"/nologo", "/fo", "res.res", "res.rc"}},
            mc = {"mc", {"msgs.mc"}},
            mt = {"mt", {"-nologo", "-manifest", "a.manifest", "b.manifest", "-out:merged.manifest"}},
            dxc_ps = {"dxc", {"-T", "ps_6_0", "-E", "ps_main", "-Fo", "ps.dxil", "shader.hlsl"}},
            dxc_vs = {"dxc", {"-T", "vs_6_0", "-E", "vs_main", "-Fo", "vs.dxil", "-Fc", "vs.asm", "shader.hlsl"}},
            dxc_cs = {"dxc", {"-T", "cs_6_5", "-E", "cs_main", "-O3", "-Fo", "cs.dxil", "-Fc", "cs.asm", "cs.hlsl"}},
            fxc = {"fxc", {"/nologo", "/T", "ps_5_0", "/E", "ps_main", "/Fo", "ps.dxbc", "/Fc", "ps.asm", "shader.hlsl"}},
            makepri = {"makepri", {"createconfig", "/cf", "priconfig.xml", "/dq", "en-US", "/o"}},
            signtool = {"signtool", {"verify", "/pa", "/v", path.join(bin, "x64", "rc.exe")}},
            uuidgen_help = {"uuidgen", {"/?"}},
        }
        if winmd then
            tests.winmdidl = {"winmdidl", {"/nologo", "/outdir:.", winmd}}
        end
        -- midl preprocesses with cl.exe (x64, native) and starts midlc.exe
        -- (ARM64 under juice: a guest starting a guest).
        local cl = os.files(path.join(os.getenv("ProgramFiles") or "", "Microsoft Visual Studio", "*", "*", "VC",
                                      "Tools", "MSVC", "*", "bin", "Hostx64", "x64", "cl.exe"))[1]
        if cl then
            tests.midl = {"midl", {"/nologo", "/env", "x64", "iface.idl"},
                          {PATH = path.directory(cl) .. ";" .. (os.getenv("PATH") or "")}}
        end
        for name, t in pairs(tests) do
            local test_envs = {}
            for k, v in pairs(envs) do test_envs[k] = v end
            for k, v in pairs(t[3] or {}) do test_envs[k] = v end
            target:add("tests", name, {tool = t[1], args = t[2], envs = test_envs,
                                       bin = bin, inputs = inputs})
        end
    end)

    on_test(function (target, opt)
        local juice = path.absolute(target:dep("juice"):targetfile())
        local work = path.join(target:autogendir(), "sdk", opt.name)
        local inputs = {}
        for _, f in ipairs(os.files(path.join(opt.inputs, "*"))) do inputs[path.filename(f)] = true end

        -- Run once in a fresh copy of the inputs; return the exit code, the
        -- console output and the files written.
        local function run(program, argv)
            os.tryrm(work)
            os.mkdir(work)
            os.cp(path.join(opt.inputs, "*"), work)
            local out, err = path.join(work, "..", opt.name .. ".out"), path.join(work, "..", opt.name .. ".err")
            local code = os.execv(program, argv, {try = true, timeout = 300000, curdir = work, envs = opt.envs,
                                                  stdout = out, stderr = err})
            local console = (io.readfile(out) or "") .. "\n--- stderr ---\n" .. (io.readfile(err) or "")
            local files = {}
            for _, f in ipairs(os.files(path.join(work, "**"))) do
                local rel = path.relative(f, work)
                if not inputs[rel] then files[rel] = io.readfile(f, {encoding = "binary"}) end
            end
            return code, console, files
        end

        local ref_code, ref_console, ref_files = run(path.join(opt.bin, "x64", opt.tool .. ".exe"), opt.args)
        local code, console, files = run(juice, table.join({path.join(opt.bin, "arm64", opt.tool .. ".exe")}, opt.args))
        opt.stdout = console
        if code ~= ref_code then
            opt.errors = string.format("exit code mismatch: juice=%s x64=%s", tostring(code), tostring(ref_code))
            return false
        end
        if console ~= ref_console then
            opt.errors = "console output mismatch\n--- juice ---\n" .. console .. "\n--- x64 ---\n" .. ref_console
            return false
        end
        for name, data in pairs(ref_files) do
            if files[name] == nil then
                opt.errors = "missing output file " .. name
                return false
            end
            if files[name] ~= data then
                opt.errors = "output file differs: " .. name
                return false
            end
        end
        for name, _ in pairs(files) do
            if ref_files[name] == nil then
                opt.errors = "unexpected output file " .. name
                return false
            end
        end
        return true
    end)
