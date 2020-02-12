const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const randombytes = @import("randombytes.zig");

const c = @cImport({
    @cInclude("sodium.h");
});

pub const PUBLICKEYBYTES = c.crypto_box_PUBLICKEYBYTES;
pub const SECRETKEYBYTES = c.crypto_box_SECRETKEYBYTES;
pub const SEALBYTES = c.crypto_box_SEALBYTES;
pub const NONCEBYTES = c.crypto_box_NONCEBYTES;
pub const MACBYTES = c.crypto_box_MACBYTES;

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
const SodiumError = error{
    KeyGenError,
    SealError,
    UnsealError,
    EncryptError,
    OpenError,
    BufferTooSmall,
};

/// Generate a public/private key pair for use in other functions in
/// this module.
pub fn keyPair(
    pub_key: *[PUBLICKEYBYTES]u8,
    secret_key: *[SECRETKEYBYTES]u8,
) SodiumError!void {
    if (c.crypto_box_keypair(pub_key, secret_key) != 0) {
        return SodiumError.KeyGenError;
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
        return SodiumError.SealError;
    }

    const cbSeal = c.crypto_box_seal;
    if (cbSeal(ciphertext.ptr, message.ptr, msgLen, recipient_pk) != 0) {
        return SodiumError.SealError;
    }
}

/// Given the private key, decrypt a message encrypted with seal.
pub fn sealOpen(
    message: []u8,
    ciphertext: []const u8,
    pub_key: *const [PUBLICKEYBYTES]u8,
    secret_key: *const [SECRETKEYBYTES]u8,
) !void {
    if (message.len < (ciphertext.len - SEALBYTES)) {
        return SodiumError.UnsealError;
    }
    const unseal = c.crypto_box_seal_open;
    const clen = ciphertext.len;
    if (unseal(
        message.ptr,
        ciphertext.ptr,
        clen,
        pub_key,
        secret_key,
    ) != 0) {
        return SodiumError.UnsealError;
    }
}

/// Authenticated public key encryption. It's important that the nonce
/// never be reused with the same keys. After encrypting with this
/// method, give ciphertext and nonce to the recipient, along with the
/// sender's public key.
///
/// The ciphertext buffer must be at least MACBYTES longer than the
/// message.
pub fn easy(
    ciphertext: []u8,
    message: []const u8,
    nonce: *const [NONCEBYTES]u8,
    recipient_pub_key: *const [PUBLICKEYBYTES]u8,
    sender_secret_key: *const [SECRETKEYBYTES]u8,
) !void {
    if (ciphertext.len < message.len + MACBYTES) {
        return SodiumError.BufferTooSmall;
    }
    if (c.crypto_box_easy(
        ciphertext.ptr,
        message.ptr,
        message.len,
        nonce,
        recipient_pub_key,
        sender_secret_key,
    ) != 0) {
        return SodiumError.EncryptError;
    }

    return;
}

/// Authenticated public key decryption. All you need is what's in the
/// arguments. The message buffer must be able to hold at least
/// (message.len - MACBYTES) bytes.
pub fn open_easy(
    message: []u8,
    ciphertext: []const u8,
    nonce: *const [NONCEBYTES]u8,
    sender_pub_key: *const [PUBLICKEYBYTES]u8,
    recipient_secret_key: *const [SECRETKEYBYTES]u8,
) !void {
    if (message.len < ciphertext.len - MACBYTES) {
        return SodiumError.BufferTooSmall;
    }

    if (c.crypto_box_open_easy(
        message.ptr,
        ciphertext.ptr,
        ciphertext.len,
        nonce,
        sender_pub_key,
        recipient_secret_key,
    ) != 0) {
        return SodiumError.OpenError;
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

test "authenticated encryption" {
    var alice_pub: [PUBLICKEYBYTES]u8 = undefined;
    var alice_priv: [SECRETKEYBYTES]u8 = undefined;
    var bob_pub: [PUBLICKEYBYTES]u8 = undefined;
    var bob_priv: [SECRETKEYBYTES]u8 = undefined;

    try keyPair(&alice_pub, &alice_priv);
    try keyPair(&bob_pub, &bob_priv);

    // Bob has a message. He generates a nonce, and uses his private
    // key and alice's public key to encrypt it.
    const msg: []const u8 = "A secret message from Bob to Alice"[0..];
    var encrypted: [msg.len + MACBYTES]u8 = undefined;
    var nonce: [NONCEBYTES]u8 = undefined;
    randombytes.buf(nonce[0..]);
    try easy(encrypted[0..], msg, &nonce, &alice_pub, &bob_priv);

    // Then Bob gives Alice his public key, the encrypted message, and
    // the nonce.
    var rcvd: [encrypted.len - MACBYTES]u8 = undefined;
    try open_easy(rcvd[0..], encrypted[0..], &nonce, &bob_pub, &alice_priv);
    testing.expectEqualSlices(u8, rcvd[0..], msg);
}
