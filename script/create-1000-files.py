#!/usr/bin/env python3
import os

# Directory where files will be created
output_dir = "tests"
os.makedirs(output_dir, exist_ok=True)

# Create 1000 files
for i in range(1, 1001):
    filename = os.path.join(output_dir, f"{i}.txt")
    with open(filename, "w") as file:
        file.write(f"Wrote file number {i}")

print(f"1000 files created in '{output_dir}' directory.")
