const std = @import("std");
const testing = std.testing;
const sodium = @import("sodium.zig");
const SodiumError = sodium.SodiumError;

const c = @cImport({
    @cInclude("sodium.h");
});

const PUBLICKEYBYTES = c.crypto_sign_PUBLICKEYBYTES;
const SECRETKEYBYTES = c.crypto_sign_SECRETKEYBYTES;
const BYTES = c.crypto_sign_BYTES;

/// Generate a key pair for signing. Don't share the secret half.
pub fn keyPair(
    pub_key: *[PUBLICKEYBYTES]u8,
    secret_key: *[SECRETKEYBYTES]u8,
) !void {
    if (c.crypto_sign_keypair(pub_key, secret_key) != 0) {
        return SodiumError.KeyGenError;
    }
}

/// Sign a message with secret_key. Puts signed result in signed_msg,
/// which must be at least BYTES larger than msg.
pub fn sign(
    signed_msg: []u8,
    message: []const u8,
    secret_key: *[SECRETKEYBYTES]u8,
) !void {
    if (signed_msg.len < message.len + BYTES) {
        return SodiumError.BufferTooSmall;
    }

    var len: c_ulonglong = undefined;
    if (c.crypto_sign(
        signed_msg.ptr,
        &len,
        message.ptr,
        message.len,
        secret_key,
    ) != 0) {
        return SodiumError.SignError;
    }

    if (len > signed_msg.len) {
        return SodiumError.BufferTooSmall;
    }
}

/// Verify the signature on signed_msg, and put the raw message in
/// msg, which must be able to hold at least (signed_msg.len - BYTES)
/// bytes. Use the signer's public key.
pub fn open(
    msg: []u8,
    signed_msg: []const u8,
    public_key: *[PUBLICKEYBYTES]u8,
) !void {
    if (msg.len + BYTES < signed_msg.len) {
        return SodiumError.BufferTooSmall;
    }

    var len: c_ulonglong = undefined;
    if (c.crypto_sign_open(
        msg.ptr,
        &len,
        signed_msg.ptr,
        signed_msg.len,
        public_key,
    ) != 0) {
        // It's an error because your program should crash if it
        // doesn't handle it.
        return SodiumError.InvalidSignature;
    }
    if (msg.len < len) {
        return SodiumError.BufferTooSmall;
    }
}

test "signature" {
    try sodium.init();
    var pub_key: [PUBLICKEYBYTES]u8 = undefined;
    var secret_key: [SECRETKEYBYTES]u8 = undefined;

    try keyPair(&pub_key, &secret_key);

    const msg = "A special message that should not be changed."[0..];
    var signed: [msg.len + BYTES]u8 = undefined;
    try sign(signed[0..], msg, &secret_key);
    var received: [signed.len - BYTES]u8 = undefined;
    try open(received[0..], signed[0..], &pub_key);
    testing.expectEqualSlices(u8, msg, received[0..]);
}
