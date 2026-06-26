"""AES-128 CBC lab skeleton.

The AES block cipher and secure random bytes come from libraries. Your job is
to implement PKCS#7 padding and CBC mode using those building blocks.
"""

from __future__ import annotations

from secrets import token_bytes

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


AES_BLOCK_SIZE = 16
AES_128_KEY_SIZE = 16


def generate_aes128_key() -> bytes:
    """Return a fresh 128-bit AES key from a cryptographically secure RNG."""
    return token_bytes(AES_128_KEY_SIZE)


def generate_iv() -> bytes:
    """Return a fresh AES block-sized IV from a cryptographically secure RNG."""
    return token_bytes(AES_BLOCK_SIZE)


def aes128_encrypt_block(key: bytes, plaintext_block: bytes) -> bytes:
    """Encrypt one 16-byte block with AES-128.

    This intentionally uses ECB for exactly one block so CBC can be implemented
    manually in this lab. Do not use this helper to encrypt a full message.
    """
    _validate_key(key)
    _validate_block(plaintext_block, "plaintext_block")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext_block) + encryptor.finalize()


def aes128_decrypt_block(key: bytes, ciphertext_block: bytes) -> bytes:
    """Decrypt one 16-byte block with AES-128."""
    _validate_key(key)
    _validate_block(ciphertext_block, "ciphertext_block")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext_block) + decryptor.finalize()


def pkcs7_pad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    """Pad data to a whole number of blocks using PKCS#7.

    Steps:
    1. Validate that block_size is between 1 and 255.
    2. Calculate how many padding bytes are needed.
    3. If data is already block-aligned, add a full padding block.
    4. Append N copies of the byte value N, where N is the padding length.
    """
    raise NotImplementedError("TODO: implement PKCS#7 padding")


def pkcs7_unpad(padded_data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    """Remove and validate PKCS#7 padding.

    Steps:
    1. Validate that block_size is between 1 and 255.
    2. Reject empty input or input whose length is not a multiple of block_size.
    3. Read the last byte to get the padding length.
    4. Reject padding lengths outside 1..block_size.
    5. Verify the final N bytes are all equal to N.
    6. Return everything except the padding bytes.
    """
    raise NotImplementedError("TODO: implement PKCS#7 unpadding")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """Return the byte-by-byte XOR of two equal-length byte strings."""
    raise NotImplementedError("TODO: implement fixed-length byte XOR")


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt a variable-length message with AES-128-CBC.

    Steps:
    1. Validate the 16-byte key and 16-byte IV.
    2. Pad plaintext with PKCS#7.
    3. Set previous_block to the IV.
    4. For each padded plaintext block:
       a. XOR the plaintext block with previous_block.
       b. AES-encrypt that XOR result.
       c. Append the ciphertext block to the output.
       d. Set previous_block to the ciphertext block.
    5. Return the joined ciphertext blocks.
    """
    raise NotImplementedError("TODO: implement AES-128-CBC encryption")


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a variable-length AES-128-CBC message and remove PKCS#7 padding.

    Steps:
    1. Validate the 16-byte key and 16-byte IV.
    2. Reject empty ciphertext or ciphertext whose length is not block-aligned.
    3. Set previous_block to the IV.
    4. For each ciphertext block:
       a. AES-decrypt the ciphertext block.
       b. XOR the decrypted block with previous_block.
       c. Append the plaintext block to the output.
       d. Set previous_block to the current ciphertext block.
    5. Remove and validate PKCS#7 padding.
    6. Return the plaintext.
    """
    raise NotImplementedError("TODO: implement AES-128-CBC decryption")


def split_blocks(data: bytes, block_size: int = AES_BLOCK_SIZE) -> list[bytes]:
    """Split already-aligned data into block_size chunks."""
    if len(data) % block_size != 0:
        raise ValueError("data length must be a multiple of block_size")
    return [data[index : index + block_size] for index in range(0, len(data), block_size)]


def _validate_key(key: bytes) -> None:
    if len(key) != AES_128_KEY_SIZE:
        raise ValueError("AES-128 keys must be exactly 16 bytes")


def _validate_iv(iv: bytes) -> None:
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("CBC IVs must be exactly 16 bytes")


def _validate_block(block: bytes, name: str) -> None:
    if len(block) != AES_BLOCK_SIZE:
        raise ValueError(f"{name} must be exactly 16 bytes")

