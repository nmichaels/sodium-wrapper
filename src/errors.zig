pub const SodiumError = error{
    KeyGenError,
    SealError,
    UnsealError,
    EncryptError,
    OpenError,
    BufferTooSmall,
    ChunkTooBig,
    InvalidCiphertext,
    InitError,
    InvalidHeader,
    SignError,
    InvalidSignature,
};
