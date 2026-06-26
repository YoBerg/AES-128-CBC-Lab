from aes_cbc_lab import cbc_decrypt, cbc_encrypt, generate_aes128_key, generate_iv


def main() -> None:
    key = generate_aes128_key()
    iv = generate_iv()
    message = b"CBC handles messages of many lengths once PKCS#7 padding is in place."

    ciphertext = cbc_encrypt(key, iv, message)
    recovered = cbc_decrypt(key, iv, ciphertext)

    print(f"Plaintext:  {message!r}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Recovered:  {recovered!r}")
    print(f"Success:    {recovered == message}")


if __name__ == "__main__":
    main()

