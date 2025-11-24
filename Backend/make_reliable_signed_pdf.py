#!/usr/bin/env python3
"""
Reliable PDF signer: creates signed-final.pdf with an embedded DER CMS signature.

Prereqs:
 - Python (use your .venv)
 - Homebrew OpenSSL available at /opt/homebrew/opt/openssl@3/bin/openssl
 - certs/signer.pem and certs/signer.key exist
 - unsigned.pdf exists in project root

How it works:
 - Append a signature block with a fixed-width ByteRange placeholder
 - Append a hex placeholder of fixed length for /Contents
 - Compute exact byte offsets, fill ByteRange with zero-padded fixed-width numbers
 - Build content.bin = bytes before < + bytes after >
 - Call openssl cms -sign to produce detached DER
 - Hex-encode DER, pad to placeholder length, swap into file (no length change)
 - Write signed-final.pdf
"""
import os, sys, subprocess
from pathlib import Path

# Config
OPENSSL = "/opt/homebrew/opt/openssl@3/bin/openssl"
PLACEHOLDER_HEX_BYTES = 65536  # big enough space for DER hex (adjust if needed)
PLACEHOLDER_HEX_LEN = PLACEHOLDER_HEX_BYTES * 2  # hex characters

project = Path.cwd()
unsigned = project / "unsigned.pdf"
signer_pem = project / "certs" / "signer.pem"
signer_key = project / "certs" / "signer.key"
ca_bundle = project / "certs" / "ca-bundle.pem"

if not unsigned.exists():
    print("ERROR: unsigned.pdf not found in", unsigned)
    sys.exit(1)
if not signer_pem.exists() or not signer_key.exists():
    print("ERROR: signer cert/key not found at certs/")
    sys.exit(1)
if not Path(OPENSSL).exists():
    print("ERROR: OpenSSL binary not found at", OPENSSL)
    sys.exit(1)

pdf_bytes = unsigned.read_bytes()

# Build signature block with fixed-width ByteRange fields (10 digits each)
# We'll use exactly 4 fields of width 10 and a single space between: "0000000000 0000000000 0000000000 0000000000"
br_numbers_template = b"0000000000 0000000000 0000000000 0000000000"
sig_block = b"\n%SIG_PLACEHOLDER\n/ByteRange [" + br_numbers_template + b"]\n/Contents <" + (b"0" * PLACEHOLDER_HEX_LEN) + b">\n%SIG_END\n"

tmp_pdf = project / "signed-with-placeholder.pdf"
tmp_pdf.write_bytes(pdf_bytes + sig_block)
print("Wrote temporary PDF:", tmp_pdf)

data = tmp_pdf.read_bytes()

# locate ByteRange and Contents positions
br_idx = data.find(b"/ByteRange [")
if br_idx == -1:
    print("ERROR: /ByteRange [ not found in temporary PDF")
    sys.exit(1)
contents_idx = data.find(b"/Contents <", br_idx)
if contents_idx == -1:
    print("ERROR: /Contents < not found after /ByteRange")
    sys.exit(1)

hex_start = data.find(b"<", contents_idx)  # position of '<'
hex_end = data.find(b">", hex_start)
if hex_start == -1 or hex_end == -1:
    print("ERROR: Could not find <...> for /Contents")
    sys.exit(1)

# Compute ByteRange values
a = 0
b_val = hex_start  # start of '<'
c = hex_end + 1
d = len(data) - c

print("Computed ByteRange (a,b,c,d):", a, b_val, c, d)

# Fill the fixed-width ByteRange numeric fields (10-digit zero-padded)
br_values_str = f"{a:010d} {b_val:010d} {c:010d} {d:010d}".encode("ascii")
# Where to write those numbers: immediately after "/ByteRange ["
nums_start = br_idx + len(b"/ByteRange [")
nums_end = nums_start + len(br_values_str)
# Build new data with ByteRange numbers filled
data_with_br = data[:nums_start] + br_values_str + data[nums_end:]

# Now build content bytes that should be signed
signed_content = data_with_br[a:b_val] + data_with_br[c:c+d]
open("content.bin", "wb").write(signed_content)
print("Wrote content.bin length:", len(signed_content))

# Create DER CMS signature over content.bin using OpenSSL (detached)
sig_der = project / "sig.der"
cmd = [
    OPENSSL, "cms", "-sign", "-binary",
    "-in", "content.bin",
    "-signer", str(signer_pem),
    "-inkey", str(signer_key),
    "-outform", "DER",
    "-out", str(sig_der)
]
print("Running OpenSSL cms -sign ...")
proc = subprocess.run(cmd, capture_output=True, text=True)
if proc.returncode != 0:
    print("OpenSSL failed:")
    print(proc.stdout)
    print(proc.stderr)
    sys.exit(1)

print("Created sig.der size:", sig_der.stat().st_size)
hex_sig = sig_der.read_bytes().hex().encode("ascii")
hex_len = len(hex_sig)
print("Hex DER length:", hex_len, "placeholder hex len:", PLACEHOLDER_HEX_LEN)

if hex_len > PLACEHOLDER_HEX_LEN:
    print("ERROR: signature hex too large for placeholder. Increase PLACEHOLDER_HEX_BYTES.")
    sys.exit(1)

# Pad signature hex to placeholder length (so we don't change file size)
padded_hex = hex_sig + (b"0" * (PLACEHOLDER_HEX_LEN - hex_len))

# Now replace the placeholder hex bytes in data_with_br between hex_start+1 and hex_end
final_data = data_with_br[:hex_start+1] + padded_hex + data_with_br[hex_end:]

signed_final = project / "signed-final.pdf"
signed_final.write_bytes(final_data)
print("Wrote final signed PDF:", signed_final)
print("Done.")
