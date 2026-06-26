from aes_cbc_lab import cbc_decrypt, cbc_encrypt
from cbc_attack_lab import (
    FORGED_COOKIE_BLOCK,
    cookie_is_admin,
    encrypt_cookie,
    forge_admin_iv,
    has_valid_padding,
    recover_plaintext_with_padding_oracle,
)


def test_bit_flipping_attack_forges_admin_cookie() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    ciphertext = encrypt_cookie(key, iv)

    forged_iv = forge_admin_iv(iv)

    assert not cookie_is_admin(key, iv, ciphertext)
    assert cookie_is_admin(key, forged_iv, ciphertext)
    assert cbc_decrypt(key, forged_iv, ciphertext).startswith(FORGED_COOKIE_BLOCK)


def test_padding_oracle_attack_recovers_plaintext() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    message = b"Observe CBC padding oracle recovery."
    ciphertext = cbc_encrypt(key, iv, message)

    def oracle(candidate_iv: bytes, candidate_ciphertext: bytes) -> bool:
        return has_valid_padding(key, candidate_iv, candidate_ciphertext)

    assert recover_plaintext_with_padding_oracle(oracle, iv, ciphertext) == message

