const std = @import("std");
const Allocator = std.mem.Allocator;
const Error = std.mem.Allocator.Error;
const testing = std.testing;
const sodium = @import("sodium.zig");
const SodiumError = sodium.SodiumError;

const c = @cImport({
    @cInclude("sodium.h");
});

/// Lock the slice to prevent swapping. Use munlock to unlock it when
/// you're done. This will fail if system limits on how much memory
/// can be locked are reached.
pub fn mlock(arr: []u8) !void {
    if (c.sodium_mlock(arr.ptr, arr.len) != 0) {
        return SodiumError.LockFailure;
    }
}

/// Unlock slice locked with mlock. Also zeroes the memory before
/// flagging the pages as swappable again.
pub fn munlock(arr: []u8) !void {
    if (c.sodium_munlock(arr.ptr, arr.len) != 0) {
        return SodiumError.UnlockFailure;
    }
}

pub fn zero(arr: []u8) void {
    c.sodium_memzero(arr.ptr, arr.len);
}

/// This allocator doesn't support realloc to make buffers bigger, and
/// won't free any memory if you try to make a buffer smaller. It
/// does, however, mlock allocated pages and zero freed memory.
pub const sodium_allocator: *Allocator = &sodium_allocator_state;
var sodium_allocator_state = Allocator{
    .allocFn = sodiumAlloc,
    .resizeFn = sodiumResize,
};

fn sodiumAlloc(
    self: *Allocator,
    len: usize,
    ptr_align: u29,
    len_align: u29,
    ret_addr: usize,
) Error![]u8 {
    var bytes = len;
    const alignment = std.math.max(ptr_align, len_align);
    if (alignment != 0) {
        bytes = std.mem.alignForward(len, alignment);
    }

    // Zig helps prevent access past the end of the slice, but that's
    // the only mechanism in cases where len_align < ptr_align. Sodium
    // will catch writes past the end of the allocated buffer.
    const slice_len = if (len_align >= ptr_align)
        bytes
    else if (len_align == 0)
        len
    else
        std.mem.alignForward(len, len_align);

    const allocated = c.sodium_malloc(bytes);
    if (allocated) |ptr| {
        return @ptrCast([*]u8, ptr)[0..slice_len];
    } else {
        return Error.OutOfMemory;
    }
}

fn sodiumResize(
    self: *Allocator,
    buf: []u8,
    buf_align: u29,
    new_len: usize,
    len_align: u29,
    ret_addr: usize,
) Error!usize {
    if (new_len > buf.len) {
        return Error.OutOfMemory;
    }
    if (new_len == 0) {
        c.sodium_free(buf.ptr);
        return 0;
    }
    const real_new_len = std.mem.alignAllocLen(buf.len, new_len, len_align);

    zero(buf[real_new_len..]);
    return real_new_len;
}

test "mem lock" {
    var data = [_]u8{0x5a} ** 128;

    try sodium.init();
    try mlock(data[0..]);
    try munlock(data[0..]);
    testing.expectEqual(data[0], 0);
}

test "mem zero" {
    var data = [_]u8{0x5a} ** 128;
    const zeroes = [_]u8{0x00} ** 128;

    try sodium.init();
    zero(data[0..]);
    testing.expectEqualSlices(u8, data[0..], zeroes[0..]);
}

test "sodium allocator" {
    const buf_size = 50;
    try sodium.init();
    var slice = try sodium_allocator.alloc(u8, buf_size);
    defer sodium_allocator.free(slice);
    var other_slice = try sodium_allocator.alloc(u8, buf_size);
    defer sodium_allocator.free(other_slice);

    for (slice) |_, idx| {
        slice[idx] = @intCast(u8, idx);
        other_slice[idx] = @intCast(u8, idx) ^ 0xff;
    }
    var sum: usize = 0;
    for (slice) |val| {
        sum += val;
    }
    testing.expectEqual(sum, 1225);
}

// expectIllegalBehavior Stolen from https://github.com/fengb/zee_alloc
// Copyright (c) 2019 Benjamin Feng
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
fn expectIllegalBehavior(context: anytype, comptime func: anytype) !void {
    if (!@hasDecl(std.os.system, "fork") or !std.debug.runtime_safety) return;

    const child_pid = try std.os.fork();
    if (child_pid == 0) {
        const null_fd = std.os.openZ("/dev/null", std.os.O_RDWR, 0) catch {
            std.debug.print("Cannot open /dev/null\n", .{});
            std.os.exit(0);
        };
        std.os.dup2(null_fd, std.io.getStdErr().handle) catch {
            std.debug.print("Cannot close child process stderr\n", .{});
            std.os.exit(0);
        };

        func(context); // this should crash
        std.os.exit(0);
    } else {
        const status = std.os.waitpid(child_pid, 0);
        // Maybe we should use a fixed error code instead of checking
        // status != 0
        if (status == 0)
            @panic("Expected illegal behavior but succeeded instead");
    }
}

fn accessPastEnd(slice: []u8) void {
    const ptr = @ptrCast([*]u8, slice.ptr);
    ptr[slice.len] = 1;
}

test "Crash" {
    try sodium.init();
    const buf_size = 1;
    var slice = sodium_allocator.alloc(u8, buf_size) catch return;
    defer sodium_allocator.free(slice);
    slice[0] = 7;
    try expectIllegalBehavior(slice, accessPastEnd);
}
