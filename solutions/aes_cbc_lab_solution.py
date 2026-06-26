"""Reference solution for the AES-128 CBC lab."""

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
    """Encrypt one 16-byte block with AES-128."""
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
    """Pad data to a whole number of blocks using PKCS#7."""
    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be between 1 and 255")

    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(padded_data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    """Remove and validate PKCS#7 padding."""
    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be between 1 and 255")
    if len(padded_data) == 0 or len(padded_data) % block_size != 0:
        raise ValueError("padded_data length must be a non-zero multiple of block_size")

    padding_length = padded_data[-1]
    if not 1 <= padding_length <= block_size:
        raise ValueError("invalid PKCS#7 padding length")
    if padded_data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("invalid PKCS#7 padding bytes")

    return padded_data[:-padding_length]


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """Return the byte-by-byte XOR of two equal-length byte strings."""
    if len(left) != len(right):
        raise ValueError("inputs must have the same length")
    return bytes(left_byte ^ right_byte for left_byte, right_byte in zip(left, right))


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt a variable-length message with AES-128-CBC."""
    _validate_key(key)
    _validate_iv(iv)

    previous_block = iv
    ciphertext_blocks = []

    for plaintext_block in split_blocks(pkcs7_pad(plaintext)):
        block_input = xor_bytes(plaintext_block, previous_block)
        ciphertext_block = aes128_encrypt_block(key, block_input)
        ciphertext_blocks.append(ciphertext_block)
        previous_block = ciphertext_block

    return b"".join(ciphertext_blocks)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a variable-length AES-128-CBC message and remove PKCS#7 padding."""
    _validate_key(key)
    _validate_iv(iv)
    if len(ciphertext) == 0 or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a non-zero multiple of AES_BLOCK_SIZE")

    previous_block = iv
    plaintext_blocks = []

    for ciphertext_block in split_blocks(ciphertext):
        block_output = aes128_decrypt_block(key, ciphertext_block)
        plaintext_blocks.append(xor_bytes(block_output, previous_block))
        previous_block = ciphertext_block

    return pkcs7_unpad(b"".join(plaintext_blocks))


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

