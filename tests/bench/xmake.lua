-- ---------------------------------------------------------------------------
-- Benchmarks
--
-- CPU-bound C programs (bench_*.c), built /O2 /MT for ARM64 and x64. Each is
-- run natively (x64) and under juice (ARM64); the outputs must match, and the
-- best wall time of several runs is reported with juice's slowdown. Results
-- are kept in build/bench/last.txt and the next run shows the change.
--
--   xmake build juice-bench
--   xmake run juice-bench [--runs=N] [--juice-args="--interp"] [name...]
-- ---------------------------------------------------------------------------
if is_plat("windows") then
target("juice-bench")
    set_kind("phony")
    set_default(false)
    add_deps("juice")

    on_load(function (target)
        import("lib.detect.find_program")
        local cc = find_program("clang-cl", {paths = {path.join(os.getenv("ProgramFiles") or "", "LLVM", "bin")}})
        local vctools = get_config("guest_vctoolsdir")
        if not vctools or vctools == "" then
            vctools = nil
            local pattern = path.join(os.getenv("ProgramFiles") or "", "Microsoft Visual Studio", "*", "*",
                                      "VC", "Tools", "MSVC", "*", "lib", "arm64", "libcmt.lib")
            for _, lib in ipairs(os.files(pattern)) do
                local dir = path.directory(path.directory(path.directory(lib)))
                if os.isfile(path.join(dir, "lib", "x64", "libcmt.lib")) then vctools = dir end
            end
        end
        if not cc or not vctools then
            print("juice: clang-cl or an MSVC toolset with ARM64 C runtime libraries not found, benchmarks disabled")
            return
        end
        local outdir = path.join(os.projectdir(), "build", "bench")
        local benches = {}
        for _, src in ipairs(os.files(path.join(target:scriptdir(), "bench_*.c"))) do
            local name = path.basename(src)
            local exes = {}
            local steps = {}
            for _, a in ipairs({{"arm64", "aarch64-pc-windows-msvc"}, {"x64", "x86_64-pc-windows-msvc"}}) do
                local exe = path.join(outdir, name .. "." .. a[1] .. ".exe")
                exes[a[1]] = exe
                table.insert(steps, {"--target=" .. a[2], "/nologo", "/O2", "/MT", "/W3", "/clang:-ffp-contract=off",
                                     "/vctoolsdir" .. vctools, src,
                                     "/Fo" .. path.join(outdir, name .. "." .. a[1] .. ".obj"), "/Fe" .. exe})
            end
            table.insert(benches, {name = name, src = src, exes = exes, steps = steps})
        end
        target:data_set("bench.cc", cc)
        target:data_set("bench.list", benches)
        target:data_set("bench.outdir", outdir)
    end)

    on_build(function (target, opt)
        import("core.project.depend")
        import("utils.progress")
        local cc = target:data("bench.cc")
        local benches = target:data("bench.list")
        if not cc or not benches then return end
        os.mkdir(target:data("bench.outdir"))
        for _, b in ipairs(benches) do
            depend.on_changed(function ()
                progress.show(opt.progress, "${color.build.object}compiling.bench %s", b.name)
                for _, argv in ipairs(b.steps) do os.vrunv(cc, argv) end
            end, {dependfile = b.exes.arm64 .. ".d", files = {b.src}, values = table.join(table.unpack(b.steps))})
        end
    end)

    on_run(function (target)
        import("core.base.option")
        local benches = target:data("bench.list")
        if not benches then
            raise("benchmarks are not configured (clang-cl and an ARM64 MSVC toolset are needed)")
        end
        local juice = path.absolute(target:dep("juice"):targetfile())
        local runs = 3
        local juice_args = {}
        local only = {}
        local filtered = false
        for _, arg in ipairs(option.get("arguments") or {}) do
            if arg:startswith("--runs=") then
                runs = tonumber(arg:sub(8))
            elseif arg:startswith("--juice-args=") then
                juice_args = arg:sub(14):split(" ")
            else
                only[arg] = true
                filtered = true
            end
        end

        local function best_time(program, argv)
            local best, out
            for _ = 1, runs do
                local start = os.mclock()
                out = os.iorunv(program, argv)
                local t = os.mclock() - start
                if not best or t < best then best = t end
            end
            return best, out
        end

        local outdir = target:data("bench.outdir")
        local last_file = path.join(outdir, "last.txt")
        local previous = {}
        if os.isfile(last_file) then
            for line in io.lines(last_file) do
                local name, ms = line:match("^(%S+)%s+(%d+)")
                if name then previous[name] = tonumber(ms) end
            end
        end

        print(string.format("%-12s %10s %10s %9s %10s", "benchmark", "native ms", "juice ms", "slowdown", "vs last"))
        local lines = {}
        local total_ratio, count = 0, 0
        for _, b in ipairs(benches) do
            if not filtered or only[b.name] or only[b.name:gsub("^bench_", "")] then
                local native_ms, native_out = best_time(b.exes.x64, {})
                local juice_ms, juice_out = best_time(juice, table.join(juice_args, {b.exes.arm64}))
                local ratio = juice_ms / math.max(native_ms, 1)
                local change = ""
                if previous[b.name] then
                    change = string.format("%+.0f%%", (juice_ms / previous[b.name] - 1) * 100)
                end
                local mismatch = juice_out ~= native_out and "  OUTPUT MISMATCH" or ""
                print(string.format("%-12s %10d %10d %8.1fx %10s%s", b.name, native_ms, juice_ms, ratio, change, mismatch))
                table.insert(lines, string.format("%s %d", b.name, juice_ms))
                total_ratio = total_ratio + math.log(ratio)
                count = count + 1
            end
        end
        if count > 0 then
            print(string.format("geometric mean slowdown: %.1fx", math.exp(total_ratio / count)))
        end
        if not filtered and #juice_args == 0 then io.writefile(last_file, table.concat(lines, "\n") .. "\n") end
    end)
end
