const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const version = std.SemanticVersion{ .major = 4, .minor = 21, .patch = 0 };

    // Dependencies
    const AFLplusplus_dep = b.dependency("AFLplusplus", .{});
    const AFLplusplus_src_path = AFLplusplus_dep.path("src/");
    const AFLplusplus_inc_path = AFLplusplus_dep.path("include/");

    // Executable suite
    const exes_step = b.step("exes", "Install executables");

    var flags = std.BoundedArray([]const u8, 15){};
    flags.appendSliceAssumeCapacity(&FLAGS);
    if (target.result.cpu.arch.isX86()) {
        flags.appendSliceAssumeCapacity(&.{ "-mavx2", "-D_HAVE_AVX2" });
    }
    if (target.query.isNative()) {
        flags.appendAssumeCapacity("-march=native");
    }

    const fuzz_exe = b.addExecutable(.{
        .name = "afl-fuzz",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    fuzz_exe.addCSourceFiles(.{
        .root = AFLplusplus_src_path,
        .files = &(FUZZ_SOURCES ++ SHARED_SOURCES),
        .flags = flags.constSlice(),
    });
    fuzz_exe.addIncludePath(AFLplusplus_inc_path);
    fuzz_exe.linkSystemLibrary("z");
    fuzz_exe.linkLibC();

    const fuzz_exe_install = b.addInstallArtifact(fuzz_exe, .{});
    exes_step.dependOn(&fuzz_exe_install.step);

    const showmap_exe = b.addExecutable(.{
        .name = "afl-showmap",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    showmap_exe.addCSourceFiles(.{
        .root = AFLplusplus_src_path,
        .files = &(.{ "afl-showmap.c", "afl-fuzz-mutators.c", "afl-fuzz-python.c" } ++ SHARED_SOURCES),
        .flags = flags.constSlice(),
    });
    showmap_exe.addIncludePath(AFLplusplus_inc_path);
    showmap_exe.linkSystemLibrary("z");
    showmap_exe.linkLibC();

    const showmap_exe_install = b.addInstallArtifact(showmap_exe, .{});
    exes_step.dependOn(&showmap_exe_install.step);

    const tmin_exe = b.addExecutable(.{
        .name = "afl-tmin",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    tmin_exe.addCSourceFiles(.{
        .root = AFLplusplus_src_path,
        .files = &(.{"afl-tmin.c"} ++ SHARED_SOURCES),
        .flags = flags.constSlice(),
    });
    tmin_exe.addIncludePath(AFLplusplus_inc_path);
    tmin_exe.linkSystemLibrary("z");
    tmin_exe.linkLibC();

    const tmin_exe_install = b.addInstallArtifact(tmin_exe, .{});
    exes_step.dependOn(&tmin_exe_install.step);

    const analyze_exe = b.addExecutable(.{
        .name = "afl-analyze",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    analyze_exe.addCSourceFiles(.{
        .root = AFLplusplus_src_path,
        .files = &(.{"afl-analyze.c"} ++ SHARED_SOURCES),
        .flags = flags.constSlice(),
    });
    analyze_exe.addIncludePath(AFLplusplus_inc_path);
    analyze_exe.linkSystemLibrary("z");
    analyze_exe.linkLibC();

    const analyze_exe_install = b.addInstallArtifact(analyze_exe, .{});
    exes_step.dependOn(&analyze_exe_install.step);

    const gotcpu_exe = b.addExecutable(.{
        .name = "afl-gotcpu",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    gotcpu_exe.addCSourceFiles(.{
        .root = AFLplusplus_src_path,
        .files = &.{ "afl-gotcpu.c", "afl-common.c" },
        .flags = flags.constSlice(),
    });
    gotcpu_exe.addIncludePath(AFLplusplus_inc_path);
    gotcpu_exe.linkSystemLibrary("z");
    gotcpu_exe.linkLibC();

    const gotcpu_exe_install = b.addInstallArtifact(gotcpu_exe, .{});
    exes_step.dependOn(&gotcpu_exe_install.step);

    const as_exe = b.addExecutable(.{
        .name = "afl-as",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    as_exe.addCSourceFiles(.{
        .root = AFLplusplus_src_path,
        .files = &.{"afl-as.c"},
        .flags = flags.constSlice(),
    });
    as_exe.addIncludePath(AFLplusplus_inc_path);
    as_exe.linkSystemLibrary("z");
    as_exe.linkLibC();

    const as_exe_install = b.addInstallArtifact(as_exe, .{});
    exes_step.dependOn(&as_exe_install.step);

    b.default_step.dependOn(exes_step);

    // Formatting checks
    const fmt_step = b.step("fmt", "Run formatting checks");

    const fmt = b.addFmt(.{
        .paths = &.{
            "build.zig",
        },
        .check = true,
    });
    fmt_step.dependOn(&fmt.step);
    b.default_step.dependOn(fmt_step);
}

const FUZZ_SOURCES = .{
    "afl-fuzz-bitmap.c",
    "afl-fuzz-cmplog.c",
    "afl-fuzz-extras.c",
    "afl-fuzz-init.c",
    "afl-fuzz-mutators.c",
    "afl-fuzz-one.c",
    "afl-fuzz-python.c",
    "afl-fuzz-queue.c",
    "afl-fuzz-redqueen.c",
    "afl-fuzz-run.c",
    "afl-fuzz-skipdet.c",
    "afl-fuzz-state.c",
    "afl-fuzz-stats.c",
    "afl-fuzz-statsd.c",
    "afl-fuzz.c",
};

const SHARED_SOURCES = .{
    "afl-performance.c",
    "afl-common.c",
    "afl-forkserver.c",
    "afl-sharedmem.c",
};

const FLAGS = .{
    "-O2",
    "-g",
    "-Wno-pointer-sign",
    "-Wno-variadic-macros",
    "-Wall",
    "-Wextra",
    "-Wno-pointer-arith",
    "-D_AFL_SPECIAL_PERFORMANCE",
    "-DHAVE_ZLIB",
    "-DAFL_PATH=\"\"",
    "-DBIN_PATH=\"\"",
    "-DDOC_PATH=\"\"",
};
