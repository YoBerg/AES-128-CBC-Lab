# AES-128 CBC Lab

## Educational Use Only

This project is a lab for educational purposes only. Do not use this code to protect real data. AES-CBC has been deprecated by industry security standards for modern application design, and writing your own cryptography is strongly advised against. In real systems, use vetted cryptographic libraries with authenticated encryption modes such as AES-GCM or ChaCha20-Poly1305.

This lab helps you implement CBC mode and PKCS#7 padding yourself while using a vetted library for the AES-128 block cipher and secure random key/IV generation.

You will write the CBC and padding logic in `aes_cbc_lab.py`. The AES primitive is already provided for you so you do not need to implement AES internals.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Your Tasks

1. Read `aes_cbc_lab.py`.
2. Implement `pkcs7_pad`.
3. Implement `pkcs7_unpad`.
4. Implement `xor_bytes`.
5. Implement `cbc_encrypt`.
6. Implement `cbc_decrypt`.
7. Run the tests:

```powershell
python -m pytest
```

The tests are intentionally written as your lab checklist. They will fail until you complete the TODOs.

## CBC Encrypt Steps

For each plaintext block:

1. Pad the full plaintext with PKCS#7.
2. Set `previous_block` to the IV.
3. XOR the current plaintext block with `previous_block`.
4. AES-encrypt the XOR result.
5. Append the ciphertext block to the output.
6. Set `previous_block` to that ciphertext block.

## CBC Decrypt Steps

For each ciphertext block:

1. Set `previous_block` to the IV.
2. AES-decrypt the current ciphertext block.
3. XOR the decrypted block with `previous_block`.
4. Append the resulting plaintext block.
5. Set `previous_block` to the current ciphertext block.
6. After all blocks are processed, remove PKCS#7 padding.

## Try It

After your implementation passes the tests:

```powershell
python example_usage.py
```

## Part 2: CBC Attack Observations

After Part 1 is working, use the added attack lab to observe two ways plain AES-CBC can fail when ciphertexts are not authenticated:

1. Bit-flipping attack: changing IV or ciphertext bits changes predictable plaintext bits after decryption.
2. Padding oracle attack: a valid/invalid padding response can leak plaintext one byte at a time.

### Part 2 Tasks

1. Read `cbc_attack_lab.py`.
2. Implement `forge_admin_iv`.
3. Implement `recover_block_with_padding_oracle`.
4. Run the Part 2 tests:

```powershell
python -m pytest tests/test_cbc_attack_lab.py tests/test_padding_oracle_false_positive.py
```

The tests are intentionally written as your Part 2 checklist. They will fail until you complete the TODOs.

Run the observation demo:

```powershell
python attack_demo.py
```

### Relevant Files

- `cbc_attack_lab.py`: small helper functions and attack observations.
- `attack_demo.py`: prints the bit-flipping and padding oracle outcomes.
- `tests/test_cbc_attack_lab.py`: checks that the attacks work against the toy CBC service.

### Bit-Flipping Study

CBC decryption uses this relationship:

```text
plaintext_block = AES_decrypt(ciphertext_block) XOR previous_block
```

For the first block, `previous_block` is the IV. If an attacker can tamper with the IV, they can flip chosen bits in the first plaintext block after decryption.

In `cbc_attack_lab.py`, the toy service starts the cookie plaintext with:

```text
admin=false;uid=
```

The function `forge_admin_iv` changes only the IV so the first decrypted block becomes:

```text
admin=true;;uid=
```

The implementation section is intentionally tiny:

1. Validate that the IV is exactly one AES block.
2. Use your Part 1 `xor_bytes` function to XOR the known original plaintext block with the desired plaintext block.
3. Use `xor_bytes` again to XOR that difference into the IV.
4. Return the forged IV.
5. Decrypt with the forged IV and observe that the key was never needed.

### Padding Oracle Study

A padding oracle is any behavior that reveals whether decrypted CBC plaintext had valid PKCS#7 padding. It could be an error message, a status code, a timing difference, or a different response body.

The toy oracle in `has_valid_padding` returns only `True` or `False`. That one bit of feedback is enough for `recover_plaintext_with_padding_oracle` to recover the plaintext.

The core idea is:

1. Pick a ciphertext block to recover.
2. Treat the previous ciphertext block, or the IV for the first block, as bytes you can modify.
3. Try byte values until the oracle says the decrypted block ends in valid padding.
4. Use that padding value to recover one plaintext byte.
5. Repeat from the end of the block to the beginning.

### Padding Oracle Implementation Steps

For one target block, use these relationships:

```text
intermediate_block = AES_decrypt(target_block)
plaintext_block = intermediate_block XOR previous_block
crafted_plaintext = intermediate_block XOR crafted_previous_block
```

Then implement `recover_block_with_padding_oracle`:

1. Validate `previous_block` and `target_block`.
2. Create 16-byte mutable arrays for `intermediate`, `plaintext`, and `crafted_previous`.
3. Start at the last byte of the block with padding value `0x01`.
4. Try all 256 possible values for that byte in `crafted_previous`.
5. When the oracle returns `True`, calculate the intermediate byte with `guess XOR padding_value`.
6. Calculate the real plaintext byte with `intermediate_byte XOR previous_block_byte`.
7. Move one byte left and increase the target padding value to `0x02`.
8. Before guessing the new byte, set every already-solved suffix byte in `crafted_previous` so the crafted plaintext suffix becomes `0x02 0x02`.
9. Repeat the same process for `0x03`, `0x04`, and so on through `0x10`.
10. Return the recovered plaintext block.

For padding value `0x01`, consider adding one extra confirmation check to avoid mistaking an already-valid original padding byte for the byte you were trying to force.

### Bonus: Padding Oracle False Positives

The oracle only says whether the final padding is valid. It does not say which padding length was valid.

When you are trying to force a final byte of `0x01`, a sequential byte search can accidentally hit a block ending in valid `0x02 0x02` first. A naive implementation may accept that earlier guess and calculate the wrong intermediate byte.

The new `tests/test_padding_oracle_false_positive.py` file constructs exactly that trap. It makes the lower byte value produce valid `0x02 0x02` padding before the real `0x01` answer appears. Your implementation should confirm the `0x01` case by changing the second-to-last crafted byte and checking that the oracle still accepts the block.

### Defensive Takeaway

AES-CBC provides confidentiality only when used correctly, but it does not provide integrity. In real systems, use an authenticated encryption mode such as AES-GCM or ChaCha20-Poly1305, or authenticate ciphertexts before decrypting them.

## Reference Solutions

Solved reference versions are available in `solutions/`. They are meant for checking your work after attempting the lab, not as the starting point.

## AI Usage Disclosure

OpenAI Codex was used to help create and revise this educational lab. Codex assisted with the Python lab skeletons, test cases, README explanations, safety disclaimer, CBC attack observation material, and reference solutions.