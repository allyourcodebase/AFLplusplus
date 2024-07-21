const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const lib_path_flag = b.fmt("-DAFL_PATH=\"{s}\"", .{b.lib_dir});
    const bin_path_flag = b.fmt("-DBIN_PATH=\"{s}\"", .{b.exe_dir});
    const version = std.SemanticVersion{ .major = 4, .minor = 21, .patch = 0 };

    // Custom options
    const use_z = b.option(bool, "use_z", "Use system zlib") orelse true;
    const use_deflate = b.option(bool, "use_deflate", "Use system libdeflate") orelse true;

    const build_nyx = b.option(bool, "build_nyx", "Build Nyx mode on Linux") orelse true;
    const enable_wafl = b.option(bool, "enable_wafl", "Enable WAFL mode on WASI") orelse true;
    const build_coresight = b.option(bool, "build_coresight", "Build CoreSight mode on ARM64 Linux") orelse true;
    const build_unicorn_aarch64 = b.option(bool, "build_unicorn_aarch64", "Build Unicorn mode on ARM64") orelse true;

    // Dependencies
    const AFLplusplus_dep = b.dependency("AFLplusplus", .{});
    const AFLplusplus_src_path = AFLplusplus_dep.path("src/");
    const AFLplusplus_utl_path = AFLplusplus_dep.path("utils/");
    const AFLplusplus_inc_path = AFLplusplus_dep.path("include/");
    const AFLplusplus_ins_path = AFLplusplus_dep.path("instrumentation/");

    // Common flags
    var flags = std.BoundedArray([]const u8, 16){};
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
    performance_obj.linkLibC();

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
    forkserver_obj.linkLibC();

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
    sharedmem_obj.linkLibC();

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
    common_obj.linkLibC();

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

    // LLVM instrumentation C flags
    var llvm_c_flags = std.BoundedArray([]const u8, 32){};
    llvm_c_flags.appendSliceAssumeCapacity(&EXE_LLVM_C_FLAGS);
    const llvm_version = std.mem.trimRight(u8, b.run(&.{ "llvm-config", "--version" }), "\n");
    var llvm_version_iter = std.mem.tokenizeScalar(u8, llvm_version, '.');
    const llvm_major = try std.fmt.parseUnsigned(u8, llvm_version_iter.next().?, 10);
    const llvm_minor = try std.fmt.parseUnsigned(u8, llvm_version_iter.next().?, 10);
    const llvm_bin_dir = std.mem.trimRight(u8, b.run(&.{ "llvm-config", "--bindir" }), "\n");
    const llvm_lib_dir = std.mem.trimRight(u8, b.run(&.{ "llvm-config", "--libdir" }), "\n");
    llvm_c_flags.appendSliceAssumeCapacity(&.{
        lib_path_flag,
        bin_path_flag,
        b.fmt("-DLLVM_MAJOR={}", .{llvm_major}),
        b.fmt("-DLLVM_MINOR={}", .{llvm_minor}),
        b.fmt("-DLLVM_VER=\"{s}\"", .{llvm_version}),
        b.fmt("-DLLVM_BINDIR=\"{s}\"", .{llvm_bin_dir}),
        b.fmt("-DLLVM_LIBDIR=\"{s}\"", .{llvm_lib_dir}),
        b.fmt("-DCLANG_BIN=\"{s}/clang\"", .{llvm_bin_dir}),
        b.fmt("-DCLANGPP_BIN=\"{s}/clang++\"", .{llvm_bin_dir}),
    });
    if (target.query.isNative()) {
        flags.appendAssumeCapacity("-march=native");
    }

    // LLVM instrumentation C++ flags
    var llvm_cpp_flags = std.BoundedArray([]const u8, 32){};
    llvm_cpp_flags.appendSliceAssumeCapacity(llvm_c_flags.constSlice());
    llvm_cpp_flags.appendSliceAssumeCapacity(&EXE_LLVM_CPP_FLAGS);
    llvm_cpp_flags.appendSliceAssumeCapacity(&.{
        b.fmt("-std={s}", .{if (llvm_major < 10) "gnu++11" else if (llvm_major < 16) "c++14" else "c++17"}),
    });
    if (enable_wafl and target.result.os.tag == .wasi) {
        llvm_cpp_flags.appendSliceAssumeCapacity(&.{ "-DNDEBUG", "-DNO_TLS" });
    }

    // LLVM instrumentation objects
    const llvm_inc_dir = std.mem.trimRight(u8, b.run(&.{ "llvm-config", "--includedir" }), "\n");
    const llvm_inc_path = std.Build.LazyPath{ .cwd_relative = llvm_inc_dir };

    const llvm_common_obj = b.addObject(.{
        .name = "afl-llvm-common",
        .pic = true,
        .target = target,
        .optimize = optimize,
    });
    llvm_common_obj.addCSourceFile(.{
        .file = AFLplusplus_ins_path.path(b, "afl-llvm-common.cc"),
        .flags = llvm_cpp_flags.constSlice(),
    });
    llvm_common_obj.addIncludePath(AFLplusplus_inc_path);
    llvm_common_obj.addIncludePath(llvm_inc_path);
    llvm_common_obj.linkLibCpp();

    const compiler_rt_obj = b.addObject(.{
        .name = "afl-compiler-rt",
        .pic = true,
        .target = target,
        .optimize = optimize,
    });
    compiler_rt_obj.addCSourceFile(.{
        .file = AFLplusplus_ins_path.path(b, "afl-compiler-rt.o.c"),
        .flags = llvm_c_flags.constSlice(),
    });
    compiler_rt_obj.addIncludePath(AFLplusplus_inc_path);
    compiler_rt_obj.linkLibC();

    // Library LLVM instrumentation suite
    const lib_llvm_step = b.step("lib_llvm", "Install library LLVM instrumentation suite");

    const llvm_pass_lib = b.addSharedLibrary(.{
        .name = "afl-llvm-pass",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    llvm_pass_lib.addCSourceFile(.{
        .file = AFLplusplus_ins_path.path(b, "afl-llvm-pass.so.cc"),
        .flags = llvm_cpp_flags.constSlice(),
    });
    llvm_pass_lib.addIncludePath(AFLplusplus_inc_path);
    llvm_pass_lib.addIncludePath(llvm_inc_path);
    llvm_pass_lib.addObject(llvm_common_obj);
    llvm_pass_lib.linkLibCpp();

    const llvm_pass_lib_install = b.addInstallArtifact(llvm_pass_lib, .{});
    lib_llvm_step.dependOn(&llvm_pass_lib_install.step);

    const llvm_lto_lib = b.addSharedLibrary(.{
        .name = "afl-llvm-lto-instrumentlist",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    llvm_lto_lib.addCSourceFile(.{
        .file = AFLplusplus_ins_path.path(b, "afl-llvm-lto-instrumentlist.so.cc"),
        .flags = llvm_cpp_flags.constSlice(),
    });
    llvm_lto_lib.addIncludePath(AFLplusplus_inc_path);
    llvm_lto_lib.addIncludePath(llvm_inc_path);
    llvm_lto_lib.addObject(llvm_common_obj);
    llvm_lto_lib.linkLibCpp();

    const llvm_lto_lib_install = b.addInstallArtifact(llvm_lto_lib, .{});
    lib_llvm_step.dependOn(&llvm_lto_lib_install.step);

    // Executable LLVM instrumentation suite
    const exe_llvm_step = b.step("exe_llvm", "Install executable LLVM instrumentation suite");

    const cc_exe = b.addExecutable(.{
        .name = "afl-cc",
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    cc_exe.addCSourceFile(.{
        .file = AFLplusplus_src_path.path(b, "afl-cc.c"),
        .flags = llvm_c_flags.constSlice(),
    });
    cc_exe.addIncludePath(AFLplusplus_inc_path);
    cc_exe.addIncludePath(AFLplusplus_ins_path);
    cc_exe.addObject(common_obj);
    cc_exe.linkLibC();

    const cc_exe_install = b.addInstallArtifact(cc_exe, .{});
    exe_llvm_step.dependOn(&cc_exe_install.step);

    const ld_lto_exe = b.addExecutable(.{
        .name = "afl-ld-lto",
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    ld_lto_exe.addCSourceFile(.{
        .file = AFLplusplus_src_path.path(b, "afl-ld-lto.c"),
        .flags = llvm_c_flags.constSlice(),
    });
    ld_lto_exe.addIncludePath(AFLplusplus_inc_path);
    ld_lto_exe.linkLibC();

    const ld_lto_exe_install = b.addInstallArtifact(ld_lto_exe, .{});
    exe_llvm_step.dependOn(&ld_lto_exe_install.step);

    b.default_step.dependOn(exe_llvm_step);

    // Executable utility suite
    const exe_utils_step = b.step("exe_utils", "Install executable utility suite");

    const network_client_exe_util = b.addExecutable(.{
        .name = "afl-network-client",
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    network_client_exe_util.addCSourceFile(.{
        .file = AFLplusplus_utl_path.path(b, "afl_network_proxy/afl-network-client.c"),
        .flags = flags.constSlice(),
    });
    if (use_deflate) {
        network_client_exe_util.root_module.addCMacro("USE_DEFLATE", "1");
        network_client_exe_util.linkSystemLibrary("deflate");
    }
    network_client_exe_util.addIncludePath(AFLplusplus_inc_path);
    network_client_exe_util.linkLibC();

    const network_client_exe_util_install = b.addInstallArtifact(network_client_exe_util, .{});
    exe_utils_step.dependOn(&network_client_exe_util_install.step);

    const network_server_exe_util = b.addExecutable(.{
        .name = "afl-network-server",
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    network_server_exe_util.addCSourceFile(.{
        .file = AFLplusplus_utl_path.path(b, "afl_network_proxy/afl-network-server.c"),
        .flags = flags.constSlice(),
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

    const network_server_exe_util_install = b.addInstallArtifact(network_server_exe_util, .{});
    exe_utils_step.dependOn(&network_server_exe_util_install.step);

    b.default_step.dependOn(exe_utils_step);

    // Library utility suite
    const lib_utils_step = b.step("lib_utils", "Install library utility suite");

    if (!target.result.os.tag.isDarwin()) {
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
            // TODO: CoreSight mode (coresight_mode/GNUmakefile)
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

    // TODO: FRIDA mode (frida_mode/GNUmakefile)

    // TODO: QEMU mode (qemu_mode/build_qemu_support.sh)

    if (build_nyx and target.result.os.tag == .linux) {
        // TODO: Nyx mode (nyx_mode/build_nyx_support.sh)
    }

    if (build_unicorn_aarch64 or !target.result.cpu.arch.isAARCH64()) {
        // TODO: Unicorn mode (unicorn_mode/build_unicorn_support.sh)
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
    "-Wall",
    "-Wextra",
    "-Wno-pointer-sign",
    "-Wno-pointer-arith",
    "-Wno-variadic-macros",
    "-DDOC_PATH=\"\"",
    "-D_AFL_SPECIAL_PERFORMANCE",
};

const EXE_LLVM_C_FLAGS = .{
    "-O3",
    "-g",
    "-funroll-loops",
    "-Wall",
    "-Wno-cast-qual",
    "-Wno-deprecated",
    "-Wno-pointer-sign",
    "-Wno-unused-result",
    "-Wno-unused-function",
    "-Wno-variadic-macros",
    "-Wno-deprecated-copy-with-dtor",
    "-DUSE_BINDIR=1",
    "-DAFL_CLANG_LDPATH=1",
    "-DAFL_REAL_LD=\"lld\"",
    "-DAFL_CLANG_FLTO=\"-flto=full\"",
};

const EXE_LLVM_CPP_FLAGS = .{
    "-fno-rtti",
    "-fno-exceptions",
    "-Wno-deprecated-declarations",
};

const LIB_FLAGS = .{
    "-O3",
    "-g",
    "-funroll-loops",
    "-Wall",
    "-Wno-pointer-sign",
    "-D_FORTIFY_SOURCE=2",
};
