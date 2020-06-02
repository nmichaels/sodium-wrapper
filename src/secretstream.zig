const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const testing = std.testing;
const sodium = @import("sodium.zig");
const SodiumError = sodium.SodiumError;

const c = @cImport({
    @cInclude("sodium.h");
});

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
pub fn initPush(
    state: *StreamState,
    header: *[HEADERBYTES]u8,
    key: *const [KEYBYTES]u8,
) !void {
    const fun = c.crypto_secretstream_xchacha20poly1305_init_push;
    if (fun(state, header, key) != 0) {
        return SodiumError.InitError;
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
) !c_ulonglong {
    var clen: c_ulonglong = undefined;
    // ciphertext length is guaranteed to always be mlen +
    // crypto_secretstream_xchacha20poly1305_ABYTES, so let's make
    // sure there's room.
    if (ciphertext.len < (message.len + ABYTES)) {
        return SodiumError.BufferTooSmall;
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
        return SodiumError.BufferTooSmall;
    }
    if (res != 0) {
        return SodiumError.EncryptError;
    }
    return clen;
}

/// Initialize state and header with key for reading. Call before
/// trying to decrypt things.
pub fn initPull(
    state: *StreamState,
    header: *const [HEADERBYTES]u8,
    key: *const [KEYBYTES]u8,
) !void {
    const fun = c.crypto_secretstream_xchacha20poly1305_init_pull;
    if (fun(state, header, key) != 0) {
        return SodiumError.InvalidHeader;
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
) !c_ulonglong {
    if (message.len < ciphertext.len - ABYTES) {
        return SodiumError.BufferTooSmall;
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
        return SodiumError.InvalidCiphertext;
    }
    if (mlen > message.len) {
        return SodiumError.BufferTooSmall;
    }
    return mlen;
}

/// Encrypt fixed-sized chunks of data, as many as you
/// want. Initialize with init, then push until you run out of data to
/// encrypt. Ciphertext will end up in a stream passed to the
/// initializer. Pass these to a ChunkDecrypter to get the plaintext
/// back.
pub fn ChunkEncrypter(chunk_size: usize, comptime StreamType: type) type {
    return struct {
        const Self = @This();
        key: [KEYBYTES]u8,
        hdr: [HEADERBYTES]u8,
        state: StreamState,
        out: StreamType,

        /// Create a new encrypter. Push chunks to encrypt.
        pub fn init(out_stream: StreamType, key: [KEYBYTES]u8) !Self {
            var st = Self{
                .key = key,
                .out = out_stream,
                .hdr = undefined,
                .state = undefined,
            };
            try initPush(&st.state, &st.hdr, &key);
            try out_stream.writeAll(&st.hdr);
            return st;
        }

        /// Call with data to encrypt it.
        pub fn pushChunk(self: *Self, msg: []const u8) !void {
            if (msg.len > chunk_size) {
                return SodiumError.ChunkTooBig;
            }
            // There's probably a better way to do this than to copy
            // the whole array over to the stack, byte by byte.
            var m: [chunk_size]u8 = [_]u8{0} ** chunk_size;
            for (msg) |val, idx| {
                m[idx] = val;
            }
            var ctxt: [chunk_size + ABYTES]u8 = undefined;
            const clen = try push(
                &self.state,
                ctxt[0..],
                msg,
                null,
                Tag.MESSAGE,
            );
            try self.out.writeAll(ctxt[0..clen]);
        }

        /// Free up all held resources.
        pub fn deinit(self: *Self) void {}
    };
}

/// ChunkEncrypter's buddy. Initialize with the same key and header
/// from one, and use it to decrypt chunks.
pub fn ChunkDecrypter(
    chunk_size: usize,
    comptime InStreamType: type,
    comptime OutStreamType: type,
) type {
    return struct {
        const Self = @This();
        key: [KEYBYTES]u8,
        hdr: [HEADERBYTES]u8,
        state: StreamState,
        in_stream: InStreamType,
        out_stream: OutStreamType,

        /// Create a new decrypter. Use the header as read from the
        /// beginning of the ciphertext.
        pub fn init(
            in_stream: InStreamType,
            out_stream: OutStreamType,
            key: [KEYBYTES]u8,
        ) !Self {
            var st = Self{
                .in_stream = in_stream,
                .out_stream = out_stream,
                .key = key,
                .hdr = undefined,
                .state = undefined,
            };
            try st.in_stream.readNoEof(&st.hdr);
            try initPull(&st.state, &st.hdr, &key);
            return st;
        }

        /// Decrypt chunks, one at a time. Returns null on the last
        /// chunk.
        pub fn pullChunk(self: *Self) !?void {
            var ciphertext: [chunk_size + ABYTES]u8 = undefined;
            var msg: [chunk_size]u8 = undefined;
            const clen = try self.in_stream.readAll(&ciphertext);
            const mlen = try pull(
                &self.state,
                &msg,
                null,
                ciphertext[0..clen],
                null,
            );
            try self.out_stream.writeAll(msg[0..mlen]);
            if (clen < ciphertext.len) {
                return null;
            }
        }

        /// Free all held resources.
        pub fn deinit(self: *Self) void {}
    };
}

test "stream" {
    try sodium.init();
    const msg = "Check check wheeee";
    const msg2 = "Eekers";
    var key: [KEYBYTES]u8 = undefined;
    var hdr: [HEADERBYTES]u8 = undefined;
    var ciphertext: [msg.len + ABYTES]u8 = undefined;
    var ciphertext2: [msg2.len + ABYTES]u8 = undefined;
    var state: StreamState = undefined;

    keygen(&key);
    try initPush(&state, &hdr, &key);
    const cl = try push(&state, ciphertext[0..], msg[0..], null, Tag.MESSAGE);
    const c2 = try push(&state, ciphertext2[0..], msg2[0..], null, Tag.MESSAGE);

    var clear: [ciphertext.len - ABYTES]u8 = undefined;
    var clear2: [ciphertext2.len - ABYTES]u8 = undefined;
    try initPull(&state, &hdr, &key);
    const len = try pull(&state, clear[0..], null, ciphertext[0..cl], null);
    testing.expectEqual(msg.len, len);
    const len2 = try pull(&state, clear2[0..], null, ciphertext2[0..c2], null);
    testing.expectEqual(msg2.len, len2);
    testing.expectEqualSlices(u8, msg[0..], clear[0..]);
    testing.expectEqualSlices(u8, msg2[0..], clear2[0..]);
}

test "chunks" {
    try sodium.init();
    const msg = "This message is longer than my chunk size!!";
    const malloc = std.heap.c_allocator;
    var key: [KEYBYTES]u8 = undefined;

    keygen(&key);
    const chunk_size = 4;
    var buf: [chunk_size * 1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const out = stream.outStream();
    const Encrypter = ChunkEncrypter(chunk_size, @TypeOf(out));
    var encrypter = try Encrypter.init(out, key);
    defer encrypter.deinit();
    var start: usize = 0;
    var chunk_count: usize = 0;
    while (start < msg.len) : (start += chunk_size) {
        const off = start + chunk_size;
        const end = if (off < msg.len) off else msg.len;
        try encrypter.pushChunk(msg[start..end]);
        chunk_count += 1;
    }

    const cipherlen = try stream.getPos();
    var cipherstream = std.io.fixedBufferStream(buf[0..cipherlen]).inStream();
    var decrypted: [chunk_size * 1024]u8 = undefined;
    var cleartext = std.io.fixedBufferStream(&decrypted);
    var clearstream = cleartext.outStream();
    const Decrypter = ChunkDecrypter(
        chunk_size,
        @TypeOf(cipherstream),
        @TypeOf(clearstream),
    );
    var decrypter = try Decrypter.init(cipherstream, clearstream, key);
    defer decrypter.deinit();

    while (chunk_count > 0) {
        decrypter.pullChunk() catch |err| {
            std.debug.warn("Unexpected error: {}\n", .{err});
            return err;
        } orelse break;
        chunk_count -= 1;
    }

    const len = try cleartext.getPos();
    testing.expectEqual(len, msg.len);
    testing.expectEqualSlices(u8, msg[0..], decrypted[0..len]);
}
