from cbc_attack_lab import run_bit_flipping_demo, run_padding_oracle_demo


def main() -> None:
    try:
        bit_flip = run_bit_flipping_demo()
        padding_oracle = run_padding_oracle_demo()
    except NotImplementedError:
        print("Finish the Part 1 CBC and PKCS#7 TODOs before running this demo.")
        return

    print("Bit-flipping attack")
    print(f"Before:   {bit_flip['original_plaintext']!r}")
    print(f"After:    {bit_flip['forged_plaintext']!r}")
    print(f"Admin before tampering: {bit_flip['is_admin_before']}")
    print(f"Admin after tampering:  {bit_flip['is_admin_after']}")
    print()

    print("Padding oracle attack")
    print(f"Ciphertext: {padding_oracle['ciphertext'].hex()}")
    print(f"Recovered:  {padding_oracle['recovered_plaintext']!r}")


if __name__ == "__main__":
    main()

