#!/usr/bin/env python3
import hashlib

# The target hash
target_hash = "7a296fab5364b34ce3e0476d55bf291bd41aa085e5ecf2a96883e593aa1836fed22f7242af48d54af18f55c8d1def13ec9314c926666a0ba63f7663500090565"

# Try all possible ASCII characters (0-255)
for i in range(256):
    # Convert the number to a byte (ASCII character)
    char = bytes([i])

    # Compute the SHA-512 hash of the character
    hash_object = hashlib.sha512(char+\01a)
    hash_hex = hash_object.hexdigest()

    # Check if the computed hash matches the target hash
    if hash_hex == target_hash:
        print(f"Found the character: {chr(i)} (ASCII: {i})")
        break
