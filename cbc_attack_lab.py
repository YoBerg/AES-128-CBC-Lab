"""CBC attack observation lab.

This file builds on `aes_cbc_lab.py`. Finish the CBC and PKCS#7 functions
there first, then run `attack_demo.py` to observe why unauthenticated CBC is
malleable and vulnerable to padding oracle leaks.
"""

from __future__ import annotations

from collections.abc import Callable

from aes_cbc_lab import (
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
    """Flip IV bits so the first plaintext block changes after decryption.

    CBC decryption calculates:

        plaintext_block = AES_decrypt(ciphertext_block) XOR previous_block

    For block 1, the previous block is the IV. Because the attacker knows the
    first plaintext block format, they can change the IV so decryption produces
    a different first block without knowing the key.

    Steps:
    1. Validate that iv is exactly one AES block.
    2. Use xor_bytes (part1) to find the difference between ORIGINAL_COOKIE_BLOCK and
       FORGED_COOKIE_BLOCK.
    3. Use xor_bytes again to apply that difference to the IV.
    4. Return the forged IV.
    """
    _validate_block(iv, "iv")
    
    raise NotImplementedError("TODO: implement the CBC bit-flipping attack")


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
    """Recover one plaintext block by asking only valid/invalid padding.

    The oracle receives a candidate previous block and the target ciphertext
    block. It returns True when decryption has valid PKCS#7 padding.

    Helpful CBC facts:
    - intermediate_block = AES_decrypt(target_block)
    - plaintext_block = intermediate_block XOR previous_block
    - crafted_plaintext = intermediate_block XOR crafted_previous_block

    Steps:
    1. Validate previous_block and target_block.
    2. Create three 16-byte mutable arrays:
       - intermediate: stores recovered AES_decrypt(target_block) bytes.
       - plaintext: stores recovered plaintext bytes.
       - crafted_previous: stores the attacker-controlled previous block.
    3. Work from the end of the block to the beginning.
    4. For the last byte, try all 256 values in crafted_previous[-1] until the
       oracle says the padding is valid. Valid padding means the last recovered
       crafted plaintext byte is 0x01.
    5. Use guess XOR padding_value to recover that byte of intermediate.
    6. Use intermediate_byte XOR original previous_block byte to recover the
       real plaintext byte.
    7. For the next byte, first set every already-solved suffix byte in
       crafted_previous so the crafted plaintext suffix becomes 0x02 0x02.
    8. Guess the next byte until the oracle accepts the padding.
    9. Repeat for padding values 0x03 through 0x10.
    10. Return the recovered plaintext block.

    Note:
    When padding_value is 1, one extra confirmation check can help avoid a false
    positive from an already-valid original padding byte.
    """
    _validate_block(previous_block, "previous_block")
    _validate_block(target_block, "target_block")
    raise NotImplementedError("TODO: implement one-block padding oracle recovery")


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
