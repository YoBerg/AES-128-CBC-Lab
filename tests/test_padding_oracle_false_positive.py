from cbc_attack_lab import recover_block_with_padding_oracle


AES_BLOCK_SIZE = 16


def test_padding_oracle_rejects_early_false_positive() -> None:
    previous_block = bytes.fromhex("00112233445566778899aabbccddeeff")
    target_block = b"T" * AES_BLOCK_SIZE

    intermediate = bytearray(bytes.fromhex("102030405060708090a0b0c0d0e00203"))
    expected_plaintext = bytes(
        intermediate_byte ^ previous_byte
        for intermediate_byte, previous_byte in zip(intermediate, previous_block)
    )

    def oracle(candidate_previous: bytes, candidate_target: bytes) -> bool:
        assert candidate_target == target_block
        crafted_plaintext = bytes(
            intermediate_byte ^ candidate_byte
            for intermediate_byte, candidate_byte in zip(intermediate, candidate_previous)
        )
        return _has_valid_pkcs7_padding(crafted_plaintext)

    false_positive_guess = intermediate[-1] ^ 0x02
    true_one_byte_guess = intermediate[-1] ^ 0x01

    assert false_positive_guess < true_one_byte_guess
    assert oracle(bytes([0] * 15 + [false_positive_guess]), target_block)
    assert oracle(bytes([0] * 15 + [true_one_byte_guess]), target_block)
    assert recover_block_with_padding_oracle(oracle, previous_block, target_block) == expected_plaintext


def _has_valid_pkcs7_padding(data: bytes) -> bool:
    padding_length = data[-1]
    if padding_length < 1 or padding_length > AES_BLOCK_SIZE:
        return False
    return data[-padding_length:] == bytes([padding_length]) * padding_length

