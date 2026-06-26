"""Reference solution for the CBC attack observation lab."""

from __future__ import annotations

from collections.abc import Callable

from solutions.aes_cbc_lab_solution import (
    AES_BLOCK_SIZE,
    cbc_decrypt,
    cbc_encrypt,
    generate_aes128_key,
    generate_iv,
    pkcs7_unpad,
    split_blocks,
    xor_bytes,
)


PaddingOracle = Callable[[bytes, bytes], bool]

ORIGINAL_COOKIE_BLOCK = b"admin=false;uid="
FORGED_COOKIE_BLOCK = b"admin=true;;uid="


def encrypt_cookie(key: bytes, iv: bytes, user_id: bytes = b"1001") -> bytes:
    """Return a toy encrypted cookie with admin=false in the first block."""
    return cbc_encrypt(key, iv, ORIGINAL_COOKIE_BLOCK + user_id)


def cookie_is_admin(key: bytes, iv: bytes, ciphertext: bytes) -> bool:
    """Decrypt the toy cookie and check whether the admin flag is set."""
    try:
        plaintext = cbc_decrypt(key, iv, ciphertext)
    except ValueError:
        return False
    return plaintext.startswith(FORGED_COOKIE_BLOCK)


def forge_admin_iv(iv: bytes) -> bytes:
    """Flip IV bits so the first plaintext block changes after decryption."""
    _validate_block(iv, "iv")
    difference = xor_bytes(ORIGINAL_COOKIE_BLOCK, FORGED_COOKIE_BLOCK)
    return xor_bytes(iv, difference)


def has_valid_padding(key: bytes, iv: bytes, ciphertext: bytes) -> bool:
    """Toy padding oracle: return only whether CBC decryption padding is valid."""
    try:
        cbc_decrypt(key, iv, ciphertext)
    except ValueError:
        return False
    return True


def recover_block_with_padding_oracle(
    oracle: PaddingOracle,
    previous_block: bytes,
    target_block: bytes,
) -> bytes:
    """Recover one plaintext block by asking only valid/invalid padding."""
    _validate_block(previous_block, "previous_block")
    _validate_block(target_block, "target_block")

    intermediate = bytearray(AES_BLOCK_SIZE)
    plaintext = bytearray(AES_BLOCK_SIZE)
    crafted_previous = bytearray(AES_BLOCK_SIZE)

    for padding_value in range(1, AES_BLOCK_SIZE + 1):
        position = AES_BLOCK_SIZE - padding_value

        for suffix_index in range(position + 1, AES_BLOCK_SIZE):
            crafted_previous[suffix_index] = intermediate[suffix_index] ^ padding_value

        for guess in range(256):
            crafted_previous[position] = guess
            candidate_previous = bytes(crafted_previous)

            if not oracle(candidate_previous, target_block):
                continue

            # This catches the padding oracle false positive described in the bonus
            if padding_value == 1:
                check_previous = bytearray(candidate_previous)
                check_previous[position - 1] ^= 1
                if not oracle(bytes(check_previous), target_block):
                    continue

            intermediate[position] = guess ^ padding_value
            plaintext[position] = intermediate[position] ^ previous_block[position]
            break
        else:
            raise RuntimeError("padding oracle attack could not recover a byte")

    return bytes(plaintext)


def recover_plaintext_with_padding_oracle(
    oracle: PaddingOracle,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    """Recover and unpad a CBC plaintext using a padding oracle."""
    _validate_block(iv, "iv")
    if len(ciphertext) == 0 or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("ciphertext must contain whole AES blocks")

    recovered = bytearray()
    previous_block = iv

    for target_block in split_blocks(ciphertext):
        recovered.extend(recover_block_with_padding_oracle(oracle, previous_block, target_block))
        previous_block = target_block

    return pkcs7_unpad(bytes(recovered))


def run_bit_flipping_demo() -> dict[str, bytes | bool]:
    """Run the bit-flipping observation with a fresh key and IV."""
    key = generate_aes128_key()
    iv = generate_iv()
    ciphertext = encrypt_cookie(key, iv)
    forged_iv = forge_admin_iv(iv)

    return {
        "original_plaintext": cbc_decrypt(key, iv, ciphertext),
        "forged_plaintext": cbc_decrypt(key, forged_iv, ciphertext),
        "is_admin_before": cookie_is_admin(key, iv, ciphertext),
        "is_admin_after": cookie_is_admin(key, forged_iv, ciphertext),
    }


def run_padding_oracle_demo(message: bytes = b"Padding oracle leaks plaintext.") -> dict[str, bytes]:
    """Run the padding oracle observation with a fresh key and IV."""
    key = generate_aes128_key()
    iv = generate_iv()
    ciphertext = cbc_encrypt(key, iv, message)

    def oracle(candidate_iv: bytes, candidate_ciphertext: bytes) -> bool:
        return has_valid_padding(key, candidate_iv, candidate_ciphertext)

    return {
        "ciphertext": ciphertext,
        "recovered_plaintext": recover_plaintext_with_padding_oracle(oracle, iv, ciphertext),
    }


def _validate_block(block: bytes, name: str) -> None:
    if len(block) != AES_BLOCK_SIZE:
        raise ValueError(f"{name} must be exactly {AES_BLOCK_SIZE} bytes")

