const std = @import("std");
const builtin = @import("builtin");
const FailStep = if (builtin.zig_version.minor == 13) @import("FailStep.zig") else std.Build.Step.Fail;

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const ptr_bit_width = target.result.ptrBitWidth();
    const lib_path_flag = b.fmt("-DAFL_PATH=\"{s}\"", .{b.lib_dir});
    const bin_path_flag = b.fmt("-DBIN_PATH=\"{s}\"", .{b.exe_dir});
    const version = std.SemanticVersion{ .major = 4, .minor = 21, .patch = 0 };

    // Custom options
    const use_z = b.option(bool, "use-z", "Use system zlib") orelse true;
    const build_coresight = b.option(bool, "build-coresight", "Build CoreSight mode on ARM64 Linux") orelse true;
    const build_unicorn_aarch64 = b.option(bool, "build-unicorn-aarch64", "Build Unicorn mode on ARM64") orelse true;
    const build_nyx = b.option(bool, "build-nyx", "Build Nyx mode on Linux") orelse true;

    // Dependencies
    const AFLplusplus_dep = b.dependency("AFLplusplus", .{});
    const AFLplusplus_root_path = AFLplusplus_dep.path(".");
    const AFLplusplus_src_path = AFLplusplus_dep.path("src/");
    const AFLplusplus_utl_path = AFLplusplus_dep.path("utils/");
    const AFLplusplus_inc_path = AFLplusplus_dep.path("include/");

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
    const exes_step = b.step("exes", "Install fuzzing tools");

    // LLVM tooling
    try setupLLVMTooling(
        b,
        target,
        optimize,
        version,
        lib_path_flag,
        bin_path_flag,
        AFLplusplus_dep,
        common_obj,
    );

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

    // Utility library suite
    const util_libs_step = b.step("util_libs", "Install utility library suite");

    if (!target.result.os.tag.isDarwin()) {
        const dislocator_lib = b.addSharedLibrary(.{
            .name = "dislocator",
            .pic = true,
            .target = target,
            .version = version,
            .optimize = optimize,
        });
        dislocator_lib.addCSourceFile(.{
            .file = AFLplusplus_utl_path.path(b, "libdislocator/libdislocator.so.c"),
            .flags = &(UTIL_LIB_FLAGS ++ .{ "-DUSEHUGEPAGE", "-DUSENAMEDPAGE" }),
        });
        dislocator_lib.addIncludePath(AFLplusplus_inc_path);
        dislocator_lib.linkLibC();

        const dislocator_lib_install = b.addInstallArtifact(dislocator_lib, .{ .dylib_symlinks = false });
        util_libs_step.dependOn(&dislocator_lib_install.step);

        const tokencap_lib = b.addSharedLibrary(.{
            .name = "tokencap",
            .pic = true,
            .target = target,
            .version = version,
            .optimize = optimize,
        });
        tokencap_lib.addCSourceFile(.{
            .file = AFLplusplus_utl_path.path(b, "libtokencap/libtokencap.so.c"),
            .flags = &UTIL_LIB_FLAGS,
        });
        tokencap_lib.addIncludePath(AFLplusplus_inc_path);
        tokencap_lib.linkLibC();

        const tokencap_lib_install = b.addInstallArtifact(tokencap_lib, .{ .dylib_symlinks = false });
        util_libs_step.dependOn(&tokencap_lib_install.step);

        if (build_coresight and target.result.cpu.arch.isAARCH64() and target.result.os.tag == .linux) {
            // TODO: CoreSight mode (coresight_mode/GNUmakefile)
        }
    }

    const socketfuzz_lib = b.addSharedLibrary(.{
        .name = "socketfuzz",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    socketfuzz_lib.addCSourceFile(.{
        .file = AFLplusplus_utl_path.path(b, "socket_fuzzing/socketfuzz.c"),
        .flags = &.{
            if (ptr_bit_width == 32) "-m32" else "-m64",
            "-Wall",
            "-Wextra",
            "-fno-sanitize=undefined",
            "-fno-sanitize-trap=undefined",
        },
    });
    socketfuzz_lib.addIncludePath(AFLplusplus_inc_path);
    socketfuzz_lib.linkLibC();

    const socketfuzz_lib_install = b.addInstallArtifact(socketfuzz_lib, .{
        .dest_sub_path = if (ptr_bit_width == 32) "socketfuzz32.so" else "socketfuzz64.so",
        .dylib_symlinks = false,
    });
    util_libs_step.dependOn(&socketfuzz_lib_install.step);

    const argvfuzz_lib = b.addSharedLibrary(.{
        .name = "argvfuzz",
        .pic = true,
        .target = target,
        .version = version,
        .optimize = optimize,
    });
    argvfuzz_lib.addCSourceFile(.{
        .file = AFLplusplus_utl_path.path(b, "argv_fuzzing/argvfuzz.c"),
        .flags = &.{
            if (ptr_bit_width == 32) "-m32" else "-m64",
            "-Wall",
            "-Wextra",
            "-fno-sanitize=undefined",
            "-fno-sanitize-trap=undefined",
        },
    });
    argvfuzz_lib.addIncludePath(AFLplusplus_inc_path);
    argvfuzz_lib.linkLibC();

    const argvfuzz_lib_install = b.addInstallArtifact(argvfuzz_lib, .{
        .dest_sub_path = if (ptr_bit_width == 32) "argvfuzz32.so" else "argvfuzz64.so",
        .dylib_symlinks = false,
    });
    util_libs_step.dependOn(&argvfuzz_lib_install.step);

    // TODO: FRIDA mode (frida_mode/GNUmakefile)

    // TODO: QEMU mode (qemu_mode/build_qemu_support.sh)

    if (build_nyx and target.result.os.tag == .linux) {
        // TODO: Nyx mode (nyx_mode/build_nyx_support.sh)
    }

    if (build_unicorn_aarch64 or !target.result.cpu.arch.isAARCH64()) {
        // TODO: Unicorn mode (unicorn_mode/build_unicorn_support.sh)
    }

    b.default_step.dependOn(util_libs_step);

    // Install afl scripts
    const scripts_step = b.step("scripts", "Install afl scripts");
    for (SCRIPTS) |script| {
        const install_script = b.addInstallBinFile(AFLplusplus_root_path.path(b, script), script);
        scripts_step.dependOn(&install_script.step);
    }
    b.default_step.dependOn(scripts_step);

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

fn setupLLVMTooling(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    version: std.SemanticVersion,
    lib_path_flag: []const u8,
    bin_path_flag: []const u8,
    AFLplusplus_dep: *std.Build.Dependency,
    common_obj: *std.Build.Step.Compile,
) !void {
    const ptr_bit_width = target.result.ptrBitWidth();
    const AFLplusplus_src_path = AFLplusplus_dep.path("src/");
    const AFLplusplus_inc_path = AFLplusplus_dep.path("include/");
    const AFLplusplus_ins_path = AFLplusplus_dep.path("instrumentation/");

    const enable_lto = b.option(bool, "enable-lto", "Enable LTO mode") orelse true;
    const enable_wafl = b.option(bool, "enable-wafl", "Enable WAFL mode on WASI") orelse false;

    // LLVM instrumentation object suite
    const llvm_objs_step = b.step("llvm_objs", "Install LLVM instrumentation object suite, requires LLVM");

    // LLVM instrumentation library suite
    const llvm_libs_step = b.step("llvm_libs", "Install LLVM instrumentation library suite, requires LLVM");

    // LLVM instrumentation executable suite
    const llvm_exes_step = b.step("llvm_exes", "Install LLVM instrumentation executable suite, requires LLVM");

    const llvm_config_path = b.findProgram(
        &.{"llvm-config"},
        b.option([]const []const u8, "llvm-config-path", "Path that contains llvm-config") orelse &.{},
    ) catch {
        const fail = FailStep.create(
            b,
            "Could not find 'llvm-config', which is required to build, set '-Dllvm-config-path' to specify a location not in PATH",
        );

        llvm_objs_step.dependOn(&fail.step);
        llvm_libs_step.dependOn(&fail.step);
        llvm_exes_step.dependOn(&fail.step);
        return;
    };

    // LLVM instrumentation C flags
    var llvm_c_flags = std.BoundedArray([]const u8, 32){};
    llvm_c_flags.appendSliceAssumeCapacity(&LLVM_EXE_C_FLAGS);
    const llvm_version = std.mem.trimRight(u8, b.run(&.{ llvm_config_path, "--version" }), "\n");
    var llvm_version_iter = std.mem.tokenizeScalar(u8, llvm_version, '.');
    const llvm_major = try std.fmt.parseUnsigned(u8, llvm_version_iter.next().?, 10);
    const llvm_minor = try std.fmt.parseUnsigned(u8, llvm_version_iter.next().?, 10);
    const llvm_bin_dir = std.mem.trimRight(u8, b.run(&.{ llvm_config_path, "--bindir" }), "\n");
    const llvm_lib_dir = std.mem.trimRight(u8, b.run(&.{ llvm_config_path, "--libdir" }), "\n");
    const llvm_lib_path = std.Build.LazyPath{ .cwd_relative = llvm_lib_dir };
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
    if (enable_lto) {
        llvm_c_flags.appendAssumeCapacity("-DAFL_CLANG_FLTO=\"-flto\"");
    } else {
        llvm_c_flags.appendAssumeCapacity("-DAFL_CLANG_FLTO=\"\"");
    }
    if (target.query.isNative()) {
        llvm_c_flags.appendAssumeCapacity("-march=native");
    }

    // LLVM instrumentation C++ flags
    var llvm_cpp_flags = std.BoundedArray([]const u8, 64){};
    llvm_cpp_flags.appendSliceAssumeCapacity(llvm_c_flags.constSlice());
    llvm_cpp_flags.appendSliceAssumeCapacity(&LLVM_EXE_CPP_FLAGS);
    llvm_cpp_flags.appendSliceAssumeCapacity(&.{
        b.fmt("-std={s}", .{if (llvm_major < 10) "gnu++11" else if (llvm_major < 16) "c++14" else "c++17"}),
    });
    if (enable_wafl and target.result.cpu.arch.isWasm()) {
        llvm_cpp_flags.appendSliceAssumeCapacity(&.{ "-DNDEBUG", "-DNO_TLS" });
    }

    inline for (LLVM_OBJ_NAMES) |NAME| {
        const has_lto = std.mem.endsWith(u8, NAME, "lto");
        if (has_lto) {
            llvm_c_flags.appendAssumeCapacity("-O0");
            if (enable_lto) {
                llvm_c_flags.appendAssumeCapacity("-flto");
            }
        }
        defer if (has_lto) {
            _ = llvm_c_flags.pop();
            if (enable_lto) {
                _ = llvm_c_flags.pop();
            }
        };
        inline for (.{ "", if (ptr_bit_width == 32) "32" else "64" }) |MODE| {
            if (MODE.len > 0) {
                llvm_c_flags.appendAssumeCapacity("-m" ++ MODE);
            }
            defer if (MODE.len > 0) {
                _ = llvm_c_flags.pop();
            };
            const obj = b.addObject(.{
                .name = NAME,
                .pic = true,
                .target = target,
                .optimize = optimize,
            });
            obj.addCSourceFile(.{
                .file = AFLplusplus_ins_path.path(b, NAME ++ ".o.c"),
                .flags = llvm_c_flags.constSlice(),
            });
            obj.addIncludePath(AFLplusplus_inc_path);
            obj.linkLibC();

            const obj_install = b.addInstallBinFile(
                obj.getEmittedBin(),
                NAME ++ if (MODE.len > 0) "-" ++ MODE else "" ++ ".o",
            );
            llvm_objs_step.dependOn(&obj_install.step);
        }
    }

    const llvm_inc_dir = std.mem.trimRight(u8, b.run(&.{ llvm_config_path, "--includedir" }), "\n");
    const llvm_inc_path = std.Build.LazyPath{ .cwd_relative = llvm_inc_dir };
    const llvm_name = b.fmt("LLVM-{}", .{llvm_major});

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
    llvm_common_obj.addLibraryPath(llvm_lib_path);
    llvm_common_obj.linkSystemLibrary(llvm_name);
    llvm_common_obj.linkLibCpp();

    var llvm_lib_names = std.BoundedArray([]const u8, 16){};
    llvm_lib_names.appendSliceAssumeCapacity(&LLVM_LIB_NAMES);
    if (enable_lto) {
        llvm_lib_names.appendSliceAssumeCapacity(&LLVM_LTO_LIB_NAMES);
    }
    for (llvm_lib_names.constSlice()) |name| {
        const lib = b.addSharedLibrary(.{
            .name = name,
            .pic = true,
            .target = target,
            .version = version,
            .optimize = optimize,
        });
        const file_name = if (std.mem.startsWith(u8, name, "cmp") or std.mem.startsWith(u8, name, "inj"))
            b.fmt("{s}.cc", .{name})
        else
            b.fmt("{s}.so.cc", .{name});
        lib.addCSourceFile(.{
            .file = AFLplusplus_ins_path.path(b, file_name),
            .flags = llvm_cpp_flags.constSlice(),
        });
        lib.addIncludePath(AFLplusplus_inc_path);
        lib.addIncludePath(llvm_inc_path);
        lib.addLibraryPath(llvm_lib_path);
        lib.linkSystemLibrary(llvm_name);
        lib.addObject(llvm_common_obj);
        lib.linkLibCpp();

        const lib_install = b.addInstallArtifact(lib, .{
            .dest_sub_path = b.fmt("{s}.so", .{name}),
            .dylib_symlinks = false,
        });
        llvm_libs_step.dependOn(&lib_install.step);
    }

    const dynamic_list_install = b.addInstallFile(AFLplusplus_dep.path("dynamic_list.txt"), "lib/dynamic_list.txt");

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
    cc_exe.addLibraryPath(llvm_lib_path);
    cc_exe.linkSystemLibrary(llvm_name);
    cc_exe.addObject(common_obj);
    cc_exe.linkLibC();

    const cc_exe_install = b.addInstallArtifact(cc_exe, .{});
    cc_exe_install.step.dependOn(&dynamic_list_install.step);
    cc_exe_install.step.dependOn(llvm_objs_step);
    cc_exe_install.step.dependOn(llvm_libs_step);
    llvm_exes_step.dependOn(&cc_exe_install.step);

    if (enable_lto) {
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
        ld_lto_exe_install.step.dependOn(&dynamic_list_install.step);
        ld_lto_exe_install.step.dependOn(llvm_objs_step);
        ld_lto_exe_install.step.dependOn(llvm_libs_step);
        llvm_exes_step.dependOn(&ld_lto_exe_install.step);
    }
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
    "-fno-sanitize=undefined",
    "-fno-sanitize-trap=undefined",
    "-DDOC_PATH=\"\"",
    "-D_AFL_SPECIAL_PERFORMANCE",
};

const LLVM_EXE_C_FLAGS = .{
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
    "-fno-sanitize=undefined",
    "-fno-sanitize-trap=undefined",
    "-Wno-deprecated-copy-with-dtor",
    "-DUSE_BINDIR=1",
    "-DAFL_REAL_LD=\"lld\"",
    "-DAFL_CLANG_LDPATH=1",
};

const LLVM_EXE_CPP_FLAGS = .{
    "-fno-rtti",
    "-Wl,-znodelete",
    "-fno-exceptions",
    "-Wno-deprecated-declarations",
};

const LLVM_OBJ_NAMES = .{
    "afl-compiler-rt",
    "afl-llvm-rt-lto",
};

const LLVM_LIB_NAMES = .{
    "afl-llvm-dict2file",
    "afl-llvm-pass",
    "cmplog-instructions-pass",
    "cmplog-routines-pass",
    "cmplog-switches-pass",
    "compare-transform-pass",
    "injection-pass",
    "SanitizerCoveragePCGUARD",
    "split-compares-pass",
    "split-switches-pass",
};

const LLVM_LTO_LIB_NAMES = .{
    "afl-llvm-lto-instrumentlist",
    "SanitizerCoverageLTO",
};

const UTIL_LIB_FLAGS = .{
    "-O3",
    "-g",
    "-funroll-loops",
    "-Wall",
    "-Wno-pointer-sign",
    "-fno-sanitize=undefined",
    "-fno-sanitize-trap=undefined",
    "-D_FORTIFY_SOURCE=2",
};

const SCRIPTS = [_][]const u8{
    "afl-addseeds",
    "afl-cmin",
    "afl-cmin.bash",
    "afl-persistent-config",
    "afl-plot",
    "afl-system-config",
    "afl-whatsup",
    "afl-wine-trace",
};
