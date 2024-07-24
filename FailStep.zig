// This file implements a fail step for the build system
// it's taken from Zig 0.14.0-dev and pasted here to be
// used temporarily while we still target Zig 0.13.0
const std = @import("std");
const Step = std.Build.Step;
const Fail = @This();

step: Step,
error_msg: []const u8,

pub const base_id: Step.Id = .custom;

pub fn create(owner: *std.Build, error_msg: []const u8) *Fail {
    const fail = owner.allocator.create(Fail) catch @panic("OOM");

    fail.* = .{
        .step = Step.init(.{
            .id = base_id,
            .name = "fail",
            .owner = owner,
            .makeFn = make,
        }),
        .error_msg = owner.dupe(error_msg),
    };

    return fail;
}

fn make(step: *Step, prog_node: std.Progress.Node) !void {
    _ = prog_node;

    const fail: *Fail = @fieldParentPtr("step", step);

    try step.result_error_msgs.append(step.owner.allocator, fail.error_msg);

    return error.MakeFailed;
}
