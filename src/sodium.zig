const std = @import("std");
const c = @cImport({
    @cInclude("sodium.h");
});

pub const crypto_box = @import("crypto_box.zig");
pub const secretstream = @import("secretstream.zig");

test "nacl" {
    _ = @import("crypto_box.zig");
    _ = @import("secretstream.zig");
    _ = @import("randombytes.zig");
}
