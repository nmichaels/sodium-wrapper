const std = @import("std");
const c = @cImport({
    @cInclude("sodium.h");
});

pub const crypto_box = @import("crypto_box.zig");
pub const crypto_sign = @import("crypto_sign.zig");
pub const secretstream = @import("secretstream.zig");
pub const randombytes = @import("randombytes.zig");
pub const SodiumError = @import("errors.zig").SodiumError;

pub fn init() !void {
    if (c.sodium_init() < 0) {
        return SodiumError.InitError;
    }
}

test "nacl" {
    _ = @import("crypto_box.zig");
    _ = @import("secretstream.zig");
    _ = @import("randombytes.zig");
    _ = @import("crypto_sign.zig");
}
