-- ---------------------------------------------------------------------------
-- Unit tests (portable core + runtime)
-- ---------------------------------------------------------------------------
target("juice-unit-tests")
    set_kind("binary")
    set_default(false)
    add_deps("juice-runtime")
    add_files("unit/*.cpp")
    add_tests("unit")

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
               "exitcode", "retcode")
    -- C runtime programs, built /MT and /MD.
    set_values("guest.crt", "crt_c.c", "crt_cpp.cpp")

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
        local function add_job(name, variant, src, deps, flags, ldflags)
            for _, a in ipairs(arches) do
                local exe = exe_name(name, variant, a[1])
                local argv = table.join({"--target=" .. a[2]}, flags, {"/" .. variant, src,
                                        "/Fo" .. path.join(outdir, name .. "-" .. variant .. "." .. a[1] .. ".obj"),
                                        "/Fe" .. exe}, ldflags)
                table.insert(jobs, {name = name .. " (" .. a[1] .. ", /" .. variant .. ")", exe = exe,
                                    argv = argv, files = table.join({src}, deps)})
            end
        end
        local function add_guest_test(name, variant, mode, opt)
            local test = table.join({guest = exe_name(name, variant, "arm64")}, opt)
            if not opt.expect_output then
                test.reference = exe_name(name, variant, "x64")
            end
            local flags = {jit = {}, interp = {"--interp"}, noopt = {"--no-opt", "--block-size=1"}}
            test.flags = flags[mode]
            target:add("tests", name .. "." .. variant .. "." .. mode, test)
        end

        -- Freestanding programs at /O2 and /Od.
        local header = path.join(scriptdir, "programs", "juice_test.h")
        local cflags = {"/nologo", "/GS-", "/Zl", "/W3", "/clang:-fno-vectorize", "/clang:-fno-slp-vectorize"}
        local ldflags = {"/link", "/entry:mainCRTStartup", "/nodefaultlib", "/subsystem:console",
                         "kernel32.lib", "user32.lib", "advapi32.lib"}
        local special = {
            winapi = {args = {"alpha", "two words"}},
            -- Returning from the entry point: compared with a fixed expectation,
            -- since natively that only ends the main thread.
            retcode = {expect_exit = 7, expect_output = "returning 7\n"},
        }
        for _, name in ipairs(target:values("guest.freestanding")) do
            local src = path.join(scriptdir, "programs", name .. ".c")
            for _, opt in ipairs({"O2", "Od"}) do
                add_job(name, opt, src, {header}, cflags, ldflags)
                for _, mode in ipairs({"jit", "interp", "noopt"}) do
                    add_guest_test(name, opt, mode, special[name] or {})
                end
            end
        end

        -- C runtime programs, /MT and /MD.
        if vctools then
            local crt_cflags = {"/nologo", "/O2", "/W3", "/EHs-c-", "/D_HAS_EXCEPTIONS=0", "/clang:-ffp-contract=off",
                                "/clang:-fno-vectorize", "/clang:-fno-slp-vectorize", "/vctoolsdir" .. vctools}
            local crt_special = {crt_c = {args = {"one", "two words"}}}
            for _, file in ipairs(target:values("guest.crt")) do
                local name = path.basename(file)
                local src = path.join(scriptdir, "programs", file)
                for _, rt in ipairs({"MT", "MD"}) do
                    add_job(name, rt, src, {}, crt_cflags, {})
                    for _, mode in ipairs({"jit", "interp"}) do
                        add_guest_test(name, rt, mode, crt_special[name] or {})
                    end
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
            depend.on_changed(function ()
                progress.show(opt.progress, "${color.build.object}compiling.guest %s", job.name)
                os.vrunv(cc, job.argv)
            end, {dependfile = job.exe .. ".d", files = job.files, values = job.argv, lastmtime = os.mtime(job.exe)})
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
