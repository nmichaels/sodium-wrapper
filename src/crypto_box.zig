const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("sodium.h");
});

pub const PUBLICKEYBYTES = c.crypto_box_PUBLICKEYBYTES;
pub const SECRETKEYBYTES = c.crypto_box_SECRETKEYBYTES;
pub const SEALBYTES = c.crypto_box_SEALBYTES;

// Wow, Sodium has bad documentation. Here, I'll reproduce all the
// comments in the header file I'm using (crypto_box.h):
//
// /*
//  * THREAD SAFETY: crypto_box_keypair() is thread-safe,
//  * provided that sodium_init() was called before.
//  *
//  * Other functions are always thread-safe.
//  */
// /* -- Precomputation interface -- */
// /* -- Ephemeral SK interface -- */
// /* -- NaCl compatibility interface ; Requires padding -- */
//
// Wasn't that enlightening?
// TODO: Figure out what kinds of errors these things can return.
const NaClError = error{
    KeyGenError,
    SealError,
    UnsealError,
};

/// Generate a public/private key pair for use in other functions in
/// this module.
pub fn keyPair(
    pubKey: *[PUBLICKEYBYTES]u8,
    privKey: *[SECRETKEYBYTES]u8,
) NaClError!void {
    if (c.crypto_box_keypair(pubKey, privKey) != 0) {
        return NaClError.KeyGenError;
    }
}

/// Turn an arbitrary length message into a ciphertext. ciphertext
/// argument must be (message length + SEALBYTES) long.
pub fn seal(
    ciphertext: []u8,
    message: []const u8,
    recipient_pk: *const [PUBLICKEYBYTES]u8,
) !void {
    const msgLen = message.len;
    const ctxtLen = ciphertext.len;
    if (ctxtLen < msgLen + SEALBYTES) {
        return NaClError.SealError;
    }

    const cbSeal = c.crypto_box_seal;
    if (cbSeal(ciphertext.ptr, message.ptr, msgLen, recipient_pk) != 0) {
        return NaClError.SealError;
    }
}

/// Given the private key, decrypt a message encrypted with seal.
pub fn sealOpen(
    message: []u8,
    ciphertext: []const u8,
    pubKey: *const [PUBLICKEYBYTES]u8,
    privKey: *const [SECRETKEYBYTES]u8,
) !void {
    if (message.len < (ciphertext.len - SEALBYTES)) {
        return NaClError.UnsealError;
    }
    const unseal = c.crypto_box_seal_open;
    const clen = ciphertext.len;
    if (unseal(
        message.ptr,
        ciphertext.ptr,
        clen,
        pubKey,
        privKey,
    ) != 0) {
        return NaClError.UnsealError;
    }
}

/// Dynamic sealing object. Uses a mem.Allocator to allocate memory
/// for ciphertext.
///
/// Example usage:
///
/// const sealer = Sealer.init(alloc, pubkey);
/// const ciphertext = try sealer.encrypt(msg);
/// defer alloc.free(ciphertext);
///
/// Decrypt with Unsealer.
pub const Sealer = struct {
    const Self = @This();
    pubkey: [PUBLICKEYBYTES]u8,
    allocator: *Allocator,

    /// Initialize and return an instance. Note that pubkey is not a
    /// pointer.
    pub fn init(allocator: *Allocator, pubkey: [PUBLICKEYBYTES]u8) Self {
        return Self{
            .pubkey = pubkey,
            .allocator = allocator,
        };
    }

    /// Encrypt msg and return the ciphertext. Note that the
    /// ciphertext is a pointer to memory allocated with the
    /// allocator, and is owned by the caller.
    pub fn encrypt(self: Self, msg: []const u8) ![]u8 {
        var ctext = try self.allocator.alloc(u8, SEALBYTES + msg.len);
        try seal(ctext, msg, &self.pubkey);
        return ctext;
    }
};

/// Dynamic unsealing object. Uses a mem.Allocator to allocate memory
/// for plaintext.
///
/// Example usage:
///
/// const unsealer = Unsealer.init(alloc, pk, sk);
/// const cleartext = try unsealer.decrypt(ciphertext);
/// defer alloc.free(cleartext);
pub const Unsealer = struct {
    const Self = @This();
    pubkey: [PUBLICKEYBYTES]u8,
    privkey: [SECRETKEYBYTES]u8,
    allocator: *Allocator,

    /// Initialize and return an instance.
    pub fn init(
        allocator: *Allocator,
        pubkey: [PUBLICKEYBYTES]u8,
        privkey: [SECRETKEYBYTES]u8,
    ) Self {
        return Self{
            .pubkey = pubkey,
            .privkey = privkey,
            .allocator = allocator,
        };
    }

    /// Decrypt ciphertext and return the plaintext message. The
    /// caller owns the returned value and is responsible for freeing
    /// it. It was allocated with the Unsealer's allocator.
    pub fn decrypt(self: Self, ciphertext: []const u8) ![]u8 {
        var msg = try self.allocator.alloc(u8, ciphertext.len - SEALBYTES);
        try sealOpen(msg, ciphertext, &self.pubkey, &self.privkey);
        return msg;
    }
};

test "seal" {
    var pk: [PUBLICKEYBYTES]u8 = undefined;
    var sk: [SECRETKEYBYTES]u8 = undefined;

    try keyPair(&pk, &sk);
    const msg = "A secret"[0..];
    var ciphertext: [SEALBYTES + msg.len]u8 = undefined;
    try seal(ciphertext[0..], msg, &pk);

    var clear: [ciphertext.len - SEALBYTES]u8 = undefined;

    try sealOpen(clear[0..], ciphertext[0..], &pk, &sk);

    testing.expectEqualSlices(u8, msg, clear[0..]);
}

test "sealer" {
    var pk: [PUBLICKEYBYTES]u8 = undefined;
    var sk: [SECRETKEYBYTES]u8 = undefined;
    try keyPair(&pk, &sk);
    const msg = "A secret"[0..];
    const malloc = std.heap.c_allocator;

    const sealer = Sealer.init(malloc, pk);
    const cipher = try sealer.encrypt(msg);
    defer malloc.free(cipher);

    const unsealer = Unsealer.init(malloc, pk, sk);
    const clear = try unsealer.decrypt(cipher);
    defer malloc.free(clear);

    testing.expectEqualSlices(u8, msg, clear);
}
