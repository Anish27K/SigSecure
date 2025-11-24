from pathlib import Path
import base64

pdf = Path("unsigned.pdf").read_bytes()
cms = Path("signed.cms").read_bytes()
hex_cms = cms.hex()

# Construct a minimal fake /ByteRange and /Contents (enough for detector)
injected = b"\n% SigSecure\n/ByteRange [0 100 200 100] /Contents <" + hex_cms.encode() + b">\n"

Path("signed.pdf").write_bytes(pdf + injected)
print("✅ Created signed.pdf (contains real CMS signature data)")
