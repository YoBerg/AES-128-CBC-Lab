import pytest

from aes_cbc_lab import (
    AES_BLOCK_SIZE,
    aes128_encrypt_block,
    cbc_decrypt,
    cbc_encrypt,
    generate_aes128_key,
    generate_iv,
    pkcs7_pad,
    pkcs7_unpad,
    xor_bytes,
)


def test_key_and_iv_generation_sizes() -> None:
    assert len(generate_aes128_key()) == AES_BLOCK_SIZE
    assert len(generate_iv()) == AES_BLOCK_SIZE


def test_aes128_encrypt_block_known_vector() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

    ciphertext = aes128_encrypt_block(key, plaintext)

    assert ciphertext == bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


def test_pkcs7_pad_adds_short_padding() -> None:
    assert pkcs7_pad(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"


def test_pkcs7_pad_adds_full_block_when_already_aligned() -> None:
    assert pkcs7_pad(b"A" * 16) == b"A" * 16 + bytes([16]) * 16


def test_pkcs7_unpad_removes_valid_padding() -> None:
    assert pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04", 16) == b"ICE ICE BABY"


@pytest.mark.parametrize(
    "bad_value",
    [
        b"",
        b"ICE ICE BABY\x05\x05\x05\x05",
        b"ICE ICE BABY\x01\x02\x03\x04",
        b"ICE ICE BABY\x00\x00\x00\x00",
    ],
)
def test_pkcs7_unpad_rejects_invalid_padding(bad_value: bytes) -> None:
    with pytest.raises(ValueError):
        pkcs7_unpad(bad_value, 16)


def test_xor_bytes() -> None:
    assert xor_bytes(bytes.fromhex("ff00aa55"), bytes.fromhex("0f0f0f0f")) == bytes.fromhex("f00fa55a")


def test_xor_bytes_rejects_mismatched_lengths() -> None:
    with pytest.raises(ValueError):
        xor_bytes(b"abc", b"abcd")


def test_cbc_encrypt_starts_with_nist_sp_800_38a_vector() -> None:
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )

    ciphertext = cbc_encrypt(key, iv, plaintext)

    assert ciphertext[:64] == bytes.fromhex(
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7"
    )
    assert len(ciphertext) == 80


@pytest.mark.parametrize(
    "message",
    [
        b"",
        b"a",
        b"short message",
        b"A" * 16,
        b"A" * 17,
        b"variable-length messages should round trip through CBC mode",
    ],
)
def test_cbc_round_trips_variable_length_messages(message: bytes) -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")

    ciphertext = cbc_encrypt(key, iv, message)

    assert ciphertext != message
    assert len(ciphertext) % AES_BLOCK_SIZE == 0
    assert cbc_decrypt(key, iv, ciphertext) == message

