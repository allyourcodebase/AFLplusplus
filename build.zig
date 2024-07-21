const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const lib_path_flag = b.fmt("-DAFL_PATH=\"{s}\"", .{b.lib_dir});
    const bin_path_flag = b.fmt("-DBIN_PATH=\"{s}\"", .{b.exe_dir});
    const version = std.SemanticVersion{ .major = 4, .minor = 21, .patch = 0 };

    // Custom options
    const use_z = b.option(bool, "use_z", "Use system zlib") orelse true;
    const use_deflate = b.option(bool, "use_deflate", "Use system libdeflate") orelse true;

    const build_nyx = b.option(bool, "build_nyx", "Build Nyx mode on Linux") orelse true;
    const build_coresight = b.option(bool, "build_coresight", "Build CoreSight mode on ARM64 Linux") orelse true;
    const build_unicorn_aarch64 = b.option(bool, "build_unicorn_aarch64", "Build Unicorn mode on ARM64") orelse true;

    // Dependencies
    const AFLplusplus_dep = b.dependency("AFLplusplus", .{});
    const AFLplusplus_src_path = AFLplusplus_dep.path("src/");
    const AFLplusplus_utl_path = AFLplusplus_dep.path("utils/");
    const AFLplusplus_inc_path = AFLplusplus_dep.path("include/");

    // Common flags
    var flags = std.BoundedArray([]const u8, 15){};
    flags.appendSliceAssumeCapacity(&EXE_FLAGS);
    flags.appendSliceAssumeCapacity(&.{ lib_path_flag, bin_path_flag });
    if (target.result.cpu.arch.isX86()) {
        flags.appendSliceAssumeCapacity(&.{ "-mavx2", "-D_HAVE_AVX2" });
    }
    if (target.query.isNative()) {
        flags.appendAssumeCapacity("-march=native");
    }

    // Common objects
    const performance_obj = b.addObject(.{
        .name = "afl-performance",
        .pic = true,
        .target = target,
        .optimize = optimize,
    });
    performance_obj.addCSourceFile(.{
        .file = AFLplusplus_src_path.path(b, "afl-performance.c"),
        .flags = flags.constSlice(),
    });
    performance_obj.addIncludePath(AFLplusplus_inc_path);

    const forkserver_obj = b.addObject(.{
        .name = "afl-forkserver",
        .pic = true,
        .target = target,
        .optimize = optimize,
    });
    forkserver_obj.addCSourceFile(.{
        .file = AFLplusplus_src_path.path(b, "afl-forkserver.c"),
        .flags = flags.constSlice(),
    });
    forkserver_obj.addIncludePath(AFLplusplus_inc_path);

    const sharedmem_obj = b.addObject(.{
        .name = "afl-sharedmem",
        .pic = true,
        .target = target,
        .optimize = optimize,
    });
    sharedmem_obj.addCSourceFile(.{
        .file = AFLplusplus_src_path.path(b, "afl-sharedmem.c"),
        .flags = flags.constSlice(),
    });
    sharedmem_obj.addIncludePath(AFLplusplus_inc_path);

    const common_obj = b.addObject(.{
        .name = "afl-common",
        .pic = true,
        .target = target,
        .optimize = optimize,
    });
    common_obj.addCSourceFile(.{
        .file = AFLplusplus_src_path.path(b, "afl-common.c"),
        .flags = flags.constSlice(),
    });
    common_obj.addIncludePath(AFLplusplus_inc_path);

    // Executable suite
    const exes_step = b.step("exes", "Install executable suite");

    const fuzz_exe = b.addExecutable(.{
        .name = "afl-fuzz",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    fuzz_exe.addCSourceFiles(.{
        .root = AFLplusplus_src_path,
        .files = &EXE_FUZZ_SOURCES,
        .flags = flags.constSlice(),
    });
    if (use_z) {
        fuzz_exe.root_module.addCMacro("HAVE_ZLIB", "");
        fuzz_exe.linkSystemLibrary("z");
    }
    fuzz_exe.addIncludePath(AFLplusplus_inc_path);
    fuzz_exe.addObject(performance_obj);
    fuzz_exe.addObject(forkserver_obj);
    fuzz_exe.addObject(sharedmem_obj);
    fuzz_exe.addObject(common_obj);
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
        .files = &.{ "afl-showmap.c", "afl-fuzz-mutators.c", "afl-fuzz-python.c" },
        .flags = flags.constSlice(),
    });
    if (use_z) {
        showmap_exe.root_module.addCMacro("HAVE_ZLIB", "");
        showmap_exe.linkSystemLibrary("z");
    }
    showmap_exe.addIncludePath(AFLplusplus_inc_path);
    showmap_exe.addObject(performance_obj);
    showmap_exe.addObject(forkserver_obj);
    showmap_exe.addObject(sharedmem_obj);
    showmap_exe.addObject(common_obj);
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
    tmin_exe.addCSourceFile(.{
        .file = AFLplusplus_src_path.path(b, "afl-tmin.c"),
        .flags = flags.constSlice(),
    });
    if (use_z) {
        tmin_exe.root_module.addCMacro("HAVE_ZLIB", "");
        tmin_exe.linkSystemLibrary("z");
    }
    tmin_exe.addIncludePath(AFLplusplus_inc_path);
    tmin_exe.addObject(performance_obj);
    tmin_exe.addObject(forkserver_obj);
    tmin_exe.addObject(sharedmem_obj);
    tmin_exe.addObject(common_obj);
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
    analyze_exe.addCSourceFile(.{
        .file = AFLplusplus_src_path.path(b, "afl-analyze.c"),
        .flags = flags.constSlice(),
    });
    if (use_z) {
        analyze_exe.root_module.addCMacro("HAVE_ZLIB", "");
        analyze_exe.linkSystemLibrary("z");
    }
    analyze_exe.addIncludePath(AFLplusplus_inc_path);
    analyze_exe.addObject(performance_obj);
    analyze_exe.addObject(forkserver_obj);
    analyze_exe.addObject(sharedmem_obj);
    analyze_exe.addObject(common_obj);
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
    gotcpu_exe.addCSourceFile(.{
        .file = AFLplusplus_src_path.path(b, "afl-gotcpu.c"),
        .flags = flags.constSlice(),
    });
    if (use_z) {
        gotcpu_exe.root_module.addCMacro("HAVE_ZLIB", "");
        gotcpu_exe.linkSystemLibrary("z");
    }
    gotcpu_exe.addIncludePath(AFLplusplus_inc_path);
    gotcpu_exe.addObject(common_obj);
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
    as_exe.addCSourceFile(.{
        .file = AFLplusplus_src_path.path(b, "afl-as.c"),
        .flags = flags.constSlice(),
    });
    if (use_z) {
        as_exe.root_module.addCMacro("HAVE_ZLIB", "");
        as_exe.linkSystemLibrary("z");
    }
    as_exe.addIncludePath(AFLplusplus_inc_path);
    as_exe.linkLibC();

    const as_exe_install = b.addInstallArtifact(as_exe, .{});
    exes_step.dependOn(&as_exe_install.step);

    b.default_step.dependOn(exes_step);

    // Executable utility suite
    const exe_utils_step = b.step("exe_utils", "Install executable utility suite");

    // TODO: LLVM instrumentation

    const network_client_exe_util = b.addExecutable(.{
        .name = "afl-network-client",
        .target = target,
        .version = version,
        .optimize = optimize,
    });

    network_client_exe_util.addCSourceFile(.{
        .file = AFLplusplus_utl_path.path(b, "afl_network_proxy/afl-network-client.c"),
        .flags = &(.{ "-Wno-pointer-sign", lib_path_flag, bin_path_flag }),
    });
    if (use_deflate) {
        network_client_exe_util.root_module.addCMacro("USE_DEFLATE", "1");
        network_client_exe_util.linkSystemLibrary("deflate");
    }
    network_client_exe_util.addIncludePath(AFLplusplus_inc_path);
    network_client_exe_util.linkLibC();

    const network_client_exe_install_util = b.addInstallArtifact(network_client_exe_util, .{});
    exe_utils_step.dependOn(&network_client_exe_install_util.step);

    const network_server_exe_util = b.addExecutable(.{
        .name = "afl-network-server",
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    network_server_exe_util.addCSourceFile(.{
        .file = AFLplusplus_utl_path.path(b, "afl_network_proxy/afl-network-server.c"),
        .flags = &(.{ "-Wno-pointer-sign", lib_path_flag, bin_path_flag }),
    });
    if (use_deflate) {
        network_server_exe_util.root_module.addCMacro("USE_DEFLATE", "1");
        network_server_exe_util.linkSystemLibrary("deflate");
    }
    network_server_exe_util.addIncludePath(AFLplusplus_inc_path);
    network_server_exe_util.addObject(forkserver_obj);
    network_server_exe_util.addObject(sharedmem_obj);
    network_server_exe_util.addObject(common_obj);
    network_server_exe_util.linkLibC();

    const network_server_exe_install_util = b.addInstallArtifact(network_server_exe_util, .{});
    exe_utils_step.dependOn(&network_server_exe_install_util.step);

    b.default_step.dependOn(exe_utils_step);

    // Library utility suite
    const lib_utils_step = b.step("lib_utils", "Install library utility suite");

    if (!target.result.os.tag.isDarwin()) {
        // TODO: GCC plugin instrumentation

        const dislocator_lib_util = b.addSharedLibrary(.{
            .name = "dislocator",
            .pic = true,
            .target = target,
            .version = version,
            .optimize = optimize,
        });
        dislocator_lib_util.addCSourceFile(.{
            .file = AFLplusplus_utl_path.path(b, "libdislocator/libdislocator.so.c"),
            .flags = &(LIB_FLAGS ++ .{ "-DUSEHUGEPAGE", "-DUSENAMEDPAGE" }),
        });
        dislocator_lib_util.addIncludePath(AFLplusplus_inc_path);
        dislocator_lib_util.linkLibC();

        const dislocator_lib_util_install = b.addInstallArtifact(dislocator_lib_util, .{});
        lib_utils_step.dependOn(&dislocator_lib_util_install.step);

        const tokencap_lib_util = b.addSharedLibrary(.{
            .name = "tokencap",
            .pic = true,
            .target = target,
            .version = version,
            .optimize = optimize,
        });
        tokencap_lib_util.addCSourceFile(.{
            .file = AFLplusplus_utl_path.path(b, "libtokencap/libtokencap.so.c"),
            .flags = &LIB_FLAGS,
        });
        tokencap_lib_util.addIncludePath(AFLplusplus_inc_path);
        tokencap_lib_util.linkLibC();

        const tokencap_lib_util_install = b.addInstallArtifact(tokencap_lib_util, .{});
        lib_utils_step.dependOn(&tokencap_lib_util_install.step);

        if (build_coresight and target.result.cpu.arch.isAARCH64() and target.result.ofmt == .elf) {
            // TODO: CoreSight mode
        }
    }

    const socketfuzz_lib_util = b.addSharedLibrary(.{
        .name = "socketfuzz",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    socketfuzz_lib_util.addCSourceFile(.{
        .file = AFLplusplus_utl_path.path(b, "socket_fuzzing/socketfuzz.c"),
        .flags = &.{ if (target.result.ptrBitWidth() == 32) "-m32" else "-m64", "-Wall", "-Wextra" },
    });
    socketfuzz_lib_util.addIncludePath(AFLplusplus_inc_path);
    socketfuzz_lib_util.linkLibC();

    const socketfuzz_lib_util_install = b.addInstallArtifact(socketfuzz_lib_util, .{});
    lib_utils_step.dependOn(&socketfuzz_lib_util_install.step);

    const argvfuzz_lib_util = b.addSharedLibrary(.{
        .name = "argvfuzz",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    argvfuzz_lib_util.addCSourceFile(.{
        .file = AFLplusplus_utl_path.path(b, "argv_fuzzing/argvfuzz.c"),
        .flags = &.{ if (target.result.ptrBitWidth() == 32) "-m32" else "-m64", "-Wall", "-Wextra" },
    });
    argvfuzz_lib_util.addIncludePath(AFLplusplus_inc_path);
    argvfuzz_lib_util.linkLibC();

    const argvfuzz_lib_util_install = b.addInstallArtifact(argvfuzz_lib_util, .{});
    lib_utils_step.dependOn(&argvfuzz_lib_util_install.step);

    // TODO: FRIDA mode

    // TODO: QEMU mode

    if (build_nyx and target.result.os.tag == .linux) {
        // TODO: Nyx mode
    }

    if (!target.result.cpu.arch.isAARCH64() or build_unicorn_aarch64) {
        // TODO: Unicorn mode
    }

    b.default_step.dependOn(lib_utils_step);

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

const EXE_FUZZ_SOURCES = .{
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

const EXE_FLAGS = .{
    "-O2",
    "-g",
    "-Wno-pointer-sign",
    "-Wno-variadic-macros",
    "-Wall",
    "-Wextra",
    "-Wno-pointer-arith",
    "-D_AFL_SPECIAL_PERFORMANCE",
    "-DDOC_PATH=\"\"",
};

const LIB_FLAGS = .{
    "-O3",
    "-g",
    "-funroll-loops",
    "-Wall",
    "-Wno-pointer-sign",
    "-D_FORTIFY_SOURCE=2",
};
