const std = @import("std");
const testing = std.testing;

const c = @cImport({
    @cInclude("sodium.h");
});

const Errors = error{BufTooBig};

pub const SEEDBYTES = c.randombytes_SEEDBYTES;

/// Return an unpredictable value in [0, 0xffffffff]
pub fn random() u32 {
    return c.randombytes_random();
}

/// Return an unpredictable value in [0, upper_bound)
pub fn uniform(upper_bound: u32) u32 {
    return c.randombytes_uniform(upper_bound);
}

/// Fill buffer with an unpredictable sequence of bytes.
pub fn buf(buffer: []u8) void {
    c.randombytes_buf(buffer.ptr, buffer.len);
}

/// Fill buffer with bytes that are indistinguishable from random
/// without seed. For a given seed, this function will always output
/// the same sequence.
pub fn buf_deterministic(buffer: []u8, seed: *const [SEEDBYTES]u8) !void {
    if (buffer.len > (1 << 38)) {
        return Errors.BufTooBig;
    }
    c.randombytes_buf_deterministic(buffer.ptr, buffer.len, seed);
}

/// Deallocate global resources used by the prng. Probably don't call
/// this.
pub fn close(void) void {
    c.randombytes_close();
}

/// Reseed the prng, if it supports this operation. This should not be
/// necessary, even after fork().
pub fn stir(void) void {
    c.randombytes_stir();
}

test "random numbers" {
    _ = random();
    _ = uniform(0xd00dface);
    var buffer = [_]u8{ 1, 2, 3, 4, 5 };
    buf(buffer[0..]);
    const seed: [SEEDBYTES]u8 = [_]u8{0} ** SEEDBYTES;
    try buf_deterministic(buffer[0..], &seed);
    const nonrandom = [_]u8{ 0xa1, 0x1f, 0x8f, 0x12, 0xd0 };
    testing.expectEqualSlices(u8, buffer[0..], nonrandom[0..]);
}
