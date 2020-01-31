const std = @import("std");
const c = @cImport({
    @cInclude("sodium.h");
});

pub const crypto_box = @import("crypto_box.zig");

test "nacl" {
    _ = @import("crypto_box.zig");
}
