const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const testing = std.testing;

const c = @cImport({
    @cInclude("sodium.h");
});

const StreamError = error{
    BufferTooShort,
    ChunkTooBig,
    EncryptError,
    InvalidCiphertext,
    InitError,
    InvalidHeader,
};

const Tag = enum {
    MESSAGE = c.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    PUSH = c.crypto_secretstream_xchacha20poly1305_TAG_PUSH,
    REKEY = c.crypto_secretstream_xchacha20poly1305_TAG_REKEY,
    FINAL = c.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
};

pub const StreamState = c.crypto_secretstream_xchacha20poly1305_state;

pub const KEYBYTES = c.crypto_secretstream_xchacha20poly1305_KEYBYTES;
pub const HEADERBYTES = c.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
pub const ABYTES = c.crypto_secretstream_xchacha20poly1305_ABYTES;

/// Generate a secret key to be used with other secretstream
/// functions.
pub fn keygen(key: *[KEYBYTES]u8) void {
    c.crypto_secretstream_xchacha20poly1305_keygen(key);
}

/// Initialize state and header with key for writing. Call before
/// trying to encrypt things.
pub fn init_push(
    state: *StreamState,
    header: *[HEADERBYTES]u8,
    key: *const [KEYBYTES]u8,
) !void {
    const fun = c.crypto_secretstream_xchacha20poly1305_init_push;
    if (fun(state, header, key) != 0) {
        return StreamError.InitError;
    }
}

/// Push the message into ciphertext. The ciphertext argument must be
/// at least ABYTES longer than the message.
pub fn push(
    state: *StreamState,
    ciphertext: []u8,
    message: []const u8,
    additional_data: ?[]const u8,
    tag: Tag,
) !void {
    var clen: c_ulonglong = undefined;
    // ciphertext length is guaranteed to always be mlen +
    // crypto_secretstream_xchacha20poly1305_ABYTES, so let's make
    // sure there's room.
    if (ciphertext.len < (message.len + ABYTES)) {
        return StreamError.BufferTooShort;
    }
    const res = c.crypto_secretstream_xchacha20poly1305_push(
        state,
        ciphertext.ptr,
        &clen,
        message.ptr,
        message.len,
        if (additional_data) |ad| ad.ptr else null,
        if (additional_data) |ad| ad.len else 0,
        @enumToInt(tag),
    );
    if (clen > ciphertext.len) {
        // I don't trust guarantees that aren't in the source code.
        return StreamError.BufferTooShort;
    }
    if (res != 0) {
        return StreamError.EncryptError;
    }
}

/// Initialize state and header with key for reading. Call before
/// trying to decrypt things.
pub fn init_pull(
    state: *StreamState,
    header: *const [HEADERBYTES]u8,
    key: *const [KEYBYTES]u8,
) !void {
    const fun = c.crypto_secretstream_xchacha20poly1305_init_pull;
    if (fun(state, header, key) != 0) {
        return StreamError.InvalidHeader;
    }
}

/// Decrypt bytes from ciphertext and put them in message. The message
/// argument must be at least (ciphertext.len - ABYTES) bytes long.
pub fn pull(
    state: *StreamState,
    message: []u8,
    tag: ?*Tag,
    ciphertext: []const u8,
    additional_data: ?[]const u8,
) !void {
    if (message.len < ciphertext.len - ABYTES) {
        return StreamError.BufferTooShort;
    }
    var mlen: c_ulonglong = undefined;
    const res = c.crypto_secretstream_xchacha20poly1305_pull(
        state,
        message.ptr,
        &mlen,
        if (tag) |t| @ptrCast(*u8, t) else null,
        ciphertext.ptr,
        ciphertext.len,
        if (additional_data) |ad| ad.ptr else null,
        if (additional_data) |ad| ad.len else 0,
    );
    if (res != 0) {
        return StreamError.InvalidCiphertext;
    }
    if (mlen > message.len) {
        return StreamError.BufferTooShort;
    }
}

/// Encrypt fixed-sized chunks of data, as many as you
/// want. Initialize with init, then push until you run out of data to
/// encrypt. Ciphertext will end up in a dynamically allocated
/// ArrayList called data. Pass these (in order) along with the header
/// stored in the hdr member through a ChunkDecrypter to get them
/// back.
///
/// A better way to do this would be to have it accept an output
/// stream that it can just dump stuff to. That's on the TODO list.
pub fn ChunkEncrypter(chunk_size: usize) type {
    return struct {
        const Self = @This();
        key: [KEYBYTES]u8,
        hdr: [HEADERBYTES]u8,
        state: StreamState,
        allocator: *Allocator,
        data: ArrayList([chunk_size + ABYTES]u8),

        /// Create a new encrypter. Push chunks to encrypt.
        pub fn init(allocator: *Allocator, key: [KEYBYTES]u8) !Self {
            var st = Self{
                .key = key,
                .allocator = allocator,
                .hdr = undefined,
                .state = undefined,
                .data = ArrayList([chunk_size + ABYTES]u8).init(allocator),
            };
            try init_push(&st.state, &st.hdr, &key);
            return st;
        }

        /// Call with data to encrypt it.
        pub fn push_chunk(self: *Self, msg: []const u8) !void {
            if (msg.len > chunk_size) {
                return StreamError.ChunkTooBig;
            }
            // There's probably a better way to do this than to copy
            // the whole array over to the stack, byte by byte.
            var m: [chunk_size]u8 = [_]u8{0} ** chunk_size;
            for (msg) |val, idx| {
                m[idx] = val;
            }
            var ctxt: [chunk_size + ABYTES]u8 = undefined;
            try push(&self.state, ctxt[0..], m[0..], null, Tag.MESSAGE);
            try self.data.append(ctxt);
        }

        /// Free up all held resources.
        pub fn deinit(self: *Self) void {
            self.data.deinit();
        }
    };
}

/// ChunkEncrypter's buddy. Initialize with the same key and header
/// from one, and use it to decrypt chunks.
pub fn ChunkDecrypter(chunk_size: usize) type {
    return struct {
        const Self = @This();
        key: [KEYBYTES]u8,
        hdr: [HEADERBYTES]u8,
        state: StreamState,
        allocator: *Allocator,
        data: ArrayList([chunk_size]u8),

        /// Create a new decrypter. Use the header as read from the
        /// beginning of the ciphertext.
        pub fn init(
            allocator: *Allocator,
            key: [KEYBYTES]u8,
            hdr: [HEADERBYTES]u8,
        ) !Self {
            var st = Self{
                .key = key,
                .allocator = allocator,
                .hdr = hdr,
                .state = undefined,
                .data = ArrayList([chunk_size]u8).init(allocator),
            };
            try init_pull(&st.state, &st.hdr, &key);
            return st;
        }

        /// Decrypt chunks, one at a time. Put decrypted data in
        /// self.data.
        pub fn pull_chunk(
            self: *Self,
            ciphertext: [chunk_size + ABYTES]u8,
        ) !void {
            var msg: [chunk_size]u8 = undefined;
            try pull(&self.state, msg[0..], null, ciphertext[0..], null);
            try self.data.append(msg);
        }

        /// Free all held resources.
        pub fn deinit(self: *Self) void {
            self.data.deinit();
        }
    };
}


test "stream" {
    const msg = "Check check wheeee";
    const msg2 = "Eekers";
    var key: [KEYBYTES]u8 = undefined;
    var hdr: [HEADERBYTES]u8 = undefined;
    var ciphertext: [msg.len + ABYTES]u8 = undefined;
    var ciphertext2: [msg2.len + ABYTES]u8 = undefined;
    var state: StreamState = undefined;

    keygen(&key);
    try init_push(&state, &hdr, &key);
    try push(&state, ciphertext[0..], msg[0..], null, Tag.MESSAGE);
    try push(&state, ciphertext2[0..], msg2[0..], null, Tag.MESSAGE);

    var clear: [ciphertext.len - ABYTES]u8 = undefined;
    var clear2: [ciphertext2.len - ABYTES]u8 = undefined;
    try init_pull(&state, &hdr, &key);
    try pull(&state, clear[0..], null, ciphertext[0..], null);
    try pull(&state, clear2[0..], null, ciphertext2[0..], null);
    testing.expectEqualSlices(u8, msg[0..], clear[0..]);
    testing.expectEqualSlices(u8, msg2[0..], clear2[0..]);
}

test "chunks" {
    const msg = "This message is longer than my chunk size.";
    const malloc = std.heap.c_allocator;
    var key: [KEYBYTES]u8 = undefined;

    keygen(&key);
    const chunk_size = 4;
    const Encrypter = ChunkEncrypter(chunk_size);
    var encrypter = try Encrypter.init(malloc, key);
    defer encrypter.deinit();
    var start: usize = 0;
    while (start < msg.len) : (start += chunk_size) {
        const off = start + chunk_size;
        const end = if (off < msg.len) off else msg.len;
        try encrypter.push_chunk(msg[start..end]);
    }

    const Decrypter = ChunkDecrypter(chunk_size);
    var decrypter = try Decrypter.init(malloc, key, encrypter.hdr);
    defer decrypter.deinit();

    for (encrypter.data.toSlice()) |chunk| {
        try decrypter.pull_chunk(chunk);
    }

    const decrypted = try malloc.alloc(u8, decrypter.data.len * chunk_size);
    defer malloc.free(decrypted);

    for (decrypter.data.toSlice()) |chunk, off| {
        const base: usize = off * chunk_size;
        var idx: usize = 0;
        while (idx < chunk_size) : (idx += 1) {
            decrypted[idx + base] = chunk[idx];
        }
    }

    testing.expectEqualSlices(u8, msg[0..], decrypted[0..msg.len]);
}
