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
    .reallocFn = sodiumRealloc,
    .shrinkFn = sodiumShrink,
};

fn sodiumRealloc(
    self: *Allocator,
    old_mem: []u8,
    old_alignment: u29,
    new_byte_count: usize,
    new_alignment: u29,
) Error![]u8 {
    if (old_mem.len != 0) {
        return Error.OutOfMemory; // Not really, but we don't have a realloc.
    }

    // new_alignment is guaranteed to be a power of 2, >= 1, so
    // subtracting 1 will give all 1s to the right of the set bit.
    const aligned_zeros = new_alignment - 1;
    var bytes = new_byte_count;
    while (bytes & aligned_zeros != 0) {
        // sodium_malloc doesn't align the return address if size
        // isn't a multiple of the required alignment, so we have to
        // round up. This is the dumb slow way, but it doesn't involve
        // any math so we can fix it later.
        bytes += 1;
    }
    const allocated = c.sodium_malloc(bytes);
    if (allocated) |ptr| {
        return @ptrCast([*]u8, ptr)[0..new_byte_count];
    } else {
        return Error.OutOfMemory;
    }
}

fn sodiumShrink(
    self: *Allocator,
    old_mem: []u8,
    old_alignment: u29,
    new_byte_count: usize,
    new_alignment: u29,
) []u8 {
    var new_mem: []u8 = undefined;
    if (new_byte_count != 0) {
        // This function isn't allowed to fail, so instead of trying
        // to allocate additional memory and move the old buffer into
        // it, we'll just pretend the buffer got smaller. This loses
        // some of libsodium's nice fencing, and it doesn't free any
        // memory, but Zig should prevent casual access to memory past
        // the end of the buffer. We'll zero the bytes we're losing,
        // just to avoid keeping potentially sensitive but unneeded
        // data in memory.
        zero(old_mem[new_byte_count..]);
        new_mem = old_mem[0..new_byte_count];
    }
    return old_mem[0..new_byte_count];
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
