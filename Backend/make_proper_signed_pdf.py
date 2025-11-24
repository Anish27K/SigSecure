#!/usr/bin/env python3
"""
Make a properly embedded, detached CMS-signed PDF.

Requirements:
 - Python in your .venv
 - OpenSSL 3 (we'll call the Homebrew path below)
 - certs/signer.pem and certs/signer.key present
 - unsigned.pdf exists in project root

This script:
 - inserts a large hex placeholder into the PDF for /Contents
 - calculates the correct /ByteRange values for the placeholder
 - writes content.bin (the bytes that should be signed)
 - calls openssl cms -sign to create a detached signature (DER)
 - embeds the DER within the PDF by hex replacing the placeholder
 - writes signed-final.pdf
"""
import os
import subprocess
from pathlib import Path

OPENSSL = "/opt/homebrew/opt/openssl@3/bin/openssl"
PLACEHOLDER_HEX_BYTES = 8192  # placeholder size in bytes (8192 bytes = 16 KB)
PLACEHOLDER_HEX_LEN = PLACEHOLDER_HEX_BYTES * 2  # hex chars

unsigned = Path("unsigned.pdf")
if not unsigned.exists():
    raise SystemExit("unsigned.pdf not found in current directory. Create it first.")

cert_dir = Path("certs")
signer_pem = cert_dir / "signer.pem"
signer_key = cert_dir / "signer.key"
if not signer_pem.exists() or not signer_key.exists():
    raise SystemExit("certs/signer.pem or certs/signer.key not found. Create them with OpenSSL first.")

# Read original PDF bytes
pdf_bytes = unsigned.read_bytes()

# Build a signature object to append which contains a placeholder Contents
placeholder_hex = ("0" * PLACEHOLDER_HEX_LEN).encode("ascii")  # zeros
# We'll append a small signature object containing /ByteRange and /Contents with placeholder
# Keep it simple and unique so we can locate it after writing.
sig_block = b"\n%SIG_PLACEHOLDER\n/ByteRange [0 %d %d %d]\n/Contents <" + placeholder_hex + b">\n%SIG_END\n"

# Write a temporary PDF with the placeholder appended
tmp_pdf = Path("signed-with-placeholder.pdf")
tmp_pdf.write_bytes(pdf_bytes + sig_block)
print("Wrote temporary PDF with placeholder ->", tmp_pdf)

# Now find where the hex placeholder starts and ends in the file
data = tmp_pdf.read_bytes()
start_marker = b"/Contents <"
start_idx = data.find(start_marker)
if start_idx == -1:
    raise SystemExit("Couldn't find /Contents < in temporary PDF")

hex_start = start_idx + len(start_marker)
# find closing '>' after hex
hex_end = data.find(b">", hex_start)
if hex_end == -1:
    raise SystemExit("Couldn't find closing '>' for Contents")

actual_hex_len = hex_end - hex_start
print("placeholder hex len found in file:", actual_hex_len)
if actual_hex_len < PLACEHOLDER_HEX_LEN:
    raise SystemExit(f"placeholder smaller than expected ({actual_hex_len} < {PLACEHOLDER_HEX_LEN})")

# Compute ByteRange values:
# a = 0
a = 0
# b = number of bytes from start (0) to the start of the <Contents> hex (i.e., hex_start)
b = hex_start
# c = position after the closing '>' (hex_end + 1)
c = hex_end + 1
# d = remaining bytes from c to EOF
d = len(data) - c
print("ByteRange values (a,b,c,d):", a, b, c, d)

# Build content.bin that OpenSSL will sign: data[a:a+b] + data[c:c+d]
content = data[a:b] + data[c:c+d]
open("content.bin", "wb").write(content)
print("Wrote content.bin (size {})".format(len(content)))

# Create detached CMS signature (DER) using openssl cms -sign (detached => omit -nodetach)
sig_der = Path("sig.der")
cmd = [
    OPENSSL, "cms", "-sign", "-binary",
    "-in", "content.bin",
    "-signer", str(signer_pem),
    "-inkey", str(signer_key),
    "-outform", "DER",
    "-out", str(sig_der)
]
print("Running OpenSSL to create detached CMS signature...")
proc = subprocess.run(cmd, capture_output=True, text=True)
if proc.returncode != 0:
    print("OpenSSL failed:")
    print(proc.stdout)
    print(proc.stderr)
    raise SystemExit("OpenSSL cms -sign returned non-zero")

print("Created CMS DER signature:", sig_der, "size:", sig_der.stat().st_size)

# Read DER and hex-encode it
sig_der_bytes = sig_der.read_bytes()
hex_sig = sig_der_bytes.hex().encode("ascii")
hex_len = len(hex_sig)
print("Hex signature length:", hex_len)

if hex_len > PLACEHOLDER_HEX_LEN:
    raise SystemExit(f"Signature too large (hex length {hex_len}) for placeholder size {PLACEHOLDER_HEX_LEN}. Increase PLACEHOLDER_HEX_BYTES and retry.")

# Replace the placeholder zeros with the real hex signature (pad rest with zeros)
padded_hex = hex_sig + b"0" * (PLACEHOLDER_HEX_LEN - hex_len)
new_data = data[:hex_start] + padded_hex + data[hex_end:]

# Write final signed PDF
final_pdf = Path("signed-final.pdf")
final_pdf.write_bytes(new_data)
print("Wrote final signed PDF:", final_pdf)
print("Done. Now verify with OpenSSL or upload to your app.")
