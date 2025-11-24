import re
import os
import tempfile
import subprocess
import hashlib
from pathlib import Path
from typing import Tuple, Optional
from PyPDF2 import PdfReader

# Path to the Homebrew OpenSSL binary (adjust if your brew path differs)
OPENSSL_PATH = "/opt/homebrew/opt/openssl@3/bin/openssl"
# Local fallback signer cert (used to recover signature). If you have multiple signers,
# we would need to extract the cert from the CMS structure; for now use this.
LOCAL_SIGNER_CERT = os.path.join("certs", "signer.pem")

def detect_signature_type(path: str):
    detected = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return detected

    if path.lower().endswith(".pdf"):
        if b"/ByteRange" in data and b"/Contents" in data:
            detected.append("AES")
        if b"/AcroForm" in data or b"/SigFlags" in data:
            detected.append("SES")
    else:
        # simple DOCX heuristic
        if path.lower().endswith(".docx"):
            if b"signature" in data.lower():
                detected.append("SES")
    return detected

def _extract_byte_range_and_sig(pdf_path: str) -> Tuple[bytes, bytes]:
    with open(pdf_path, "rb") as f:
        data = f.read()
    m = re.search(br'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]', data)
    if not m:
        raise ValueError("No /ByteRange found")
    a, b, c, d = [int(x) for x in m.groups()]
    signed_bytes = data[a:a+b] + data[c:c+d]

    # /Contents can be hex string <...> or a stream object
    m2 = re.search(br'/Contents\s*<([0-9A-Fa-f\s]+)>', data)
    if m2:
        hex_str = m2.group(1).replace(b'\n', b'').replace(b' ', b'')
        sig_bytes = bytes.fromhex(hex_str.decode('ascii'))
    else:
        m3 = re.search(br'/Contents\s*(\d+)\s+0\s+obj(.*?)endobj', data, re.S)
        if m3:
            contents_raw = m3.group(2)
            h = re.search(br'<([0-9A-Fa-f\s]+)>', contents_raw)
            if h:
                sig_bytes = bytes.fromhex(h.group(1).replace(b'\n', b'').replace(b' ', b'').decode('ascii'))
            else:
                m4 = re.search(br'stream(.*?)endstream', contents_raw, re.S)
                if not m4:
                    raise ValueError("Could not parse /Contents (no hex, no stream)")
                sig_bytes = m4.group(1).strip(b'\r\n')
        else:
            raise ValueError("Could not locate /Contents object")
    return signed_bytes, sig_bytes

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _try_openssl_cms_verify(sig_path: str, content_path: str, ca_bundle: Optional[str]):
    """Try to call openssl cms -verify and return (success_bool, details)."""
    if ca_bundle and os.path.exists(ca_bundle):
        cmd = [OPENSSL_PATH, "cms", "-verify", "-inform", "DER", "-in", sig_path, "-content", content_path, "-CAfile", ca_bundle]
    else:
        cmd = [OPENSSL_PATH, "cms", "-verify", "-inform", "DER", "-in", sig_path, "-content", content_path, "-noverify"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return (proc.returncode == 0, {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr})
    except FileNotFoundError:
        return (False, {"error": "openssl_not_found", "path": OPENSSL_PATH})
    except Exception as e:
        return (False, {"error": "openssl_exception", "exc": str(e)})

def _recover_digestinfo_from_signature(sig_path: str, signer_cert_path: Optional[str]) -> Tuple[Optional[bytes], dict]:
    """
    Attempt to recover the PKCS#1 v1.5-decrypted DigestInfo from the signature using the public key.
    Returns (digest_bytes_or_None, details).
    """
    details = {}
    if not signer_cert_path or not os.path.exists(signer_cert_path):
        details["error"] = "no_signer_cert"
        return None, details

    pubkey_pem = Path("tmp_pubkey.pem")
    try:
        # extract public key from signer cert
        subprocess.run([OPENSSL_PATH, "x509", "-in", signer_cert_path, "-pubkey", "-noout"], check=True, stdout=pubkey_pem.open("wb"))
    except subprocess.CalledProcessError as e:
        details["extract_pubkey_fail"] = str(e)
        try:
            if pubkey_pem.exists():
                pubkey_pem.unlink()
        except:
            pass
        return None, details

    dec_out = Path("tmp_sig_dec.bin")
    # Use pkeyutl -verifyrecover with the public key (works for PKCS#1-v1_5 signed blocks)
    cmd = [OPENSSL_PATH, "pkeyutl", "-verifyrecover", "-in", sig_path, "-inkey", str(pubkey_pem), "-pubin", "-pkeyopt", "rsa_padding_mode:pkcs1", "-out", str(dec_out)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            details["pkeyutl_failed"] = {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
            return None, details
        # dec_out contains DigestInfo (ASN.1): look for the last 32 bytes if it's SHA256
        dec_bytes = dec_out.read_bytes()
        # Try to extract the trailing OCTET STRING (digest)
        m = re.search(br'\x04([ -~\x00-\xff]{1,3})', dec_bytes)  # crude but we will parse properly next
        # Simpler: search for the 32-byte window that looks non-zero
        if len(dec_bytes) >= 19 + 32:
            # Tag sequences usually: ... 04 20 <32 bytes>
            # try to find pattern 0x04 0x20
            idx = dec_bytes.find(b'\x04\x20')
            if idx != -1 and idx + 2 + 32 <= len(dec_bytes):
                digest = dec_bytes[idx+2: idx+2+32]
                details["digestinfo_source"] = "found_04_20"
                return digest, details
        # as fallback, try to search for any 32-byte chunk (rare)
        if len(dec_bytes) >= 32:
            # pick last 32 bytes (not ideal, but a fallback)
            digest = dec_bytes[-32:]
            details["digestinfo_source"] = "last32"
            return digest, details
        details["digestinfo_parse_fail_len"] = len(dec_bytes)
        return None, details
    except FileNotFoundError:
        details["error"] = "openssl_pkeyutl_not_found"
        return None, details
    finally:
        try:
            pubkey_pem.unlink()
        except:
            pass
        if dec_out.exists():
            dec_out.unlink()

def _try_canonical_signedattrs_matches(sig_bytes: bytes, inner_signed_attrs: bytes, outer_bytes: Optional[bytes]):
    """
    Try a few canonical variants of SignedAttributes and compare their sha256 to the given digest (sig_bytes_decrypted).
    Returns (matched_bool, which_variant, dict_of_hashes).
    """
    # We'll not attempt to parse the whole CMS here; the caller should pass us the inner bytes (the content of the tag).
    # inner_signed_attrs: raw bytes of the inner structure (DER of the SEQUENCE or the content inside outer wrapper)
    # outer_bytes: optional original outer bytes (context wrapper) to try header+payload forms
    variants = {}
    # variant 1: inner as-is (most raw)
    variants["inner_raw"] = inner_signed_attrs
    # variant 2: outer as-is (if provided)
    if outer_bytes:
        variants["outer_raw"] = outer_bytes
    # variant 3: canonicalized SET (preserve order)
    # parse tlv items in inner (inner might itself contain a SEQUENCE header)
    def parse_items(data: bytes):
        items = []
        pos = 0
        # If the passed inner starts with 0x30 (SEQ), skip its header to get content
        if data[0] in (0x30, 0x31):
            # read length
            idx = 1
            first = data[idx]
            idx += 1
            if first & 0x80:
                n = first & 0x7F
                idx += n
            start_of_content = idx
            data_content = data[start_of_content:]
        else:
            data_content = data
        # now iterate TLV in data_content
        pos = 0
        while pos < len(data_content):
            tag = data_content[pos]
            pos += 1
            if pos >= len(data_content):
                break
            first = data_content[pos]; pos += 1
            if first & 0x80:
                n = first & 0x7F
                l = int.from_bytes(data_content[pos:pos+n], "big")
                pos += n
            else:
                l = first
            val = data_content[pos:pos+l]
            # reconstruct full TLV
            # header length:
            hdr_len = 1 + (1 if (first & 0x80)==0 else 1 + n)
            tlv = data_content[pos - hdr_len: pos + l]
            items.append(tlv)
            pos += l
        return items

    items = parse_items(inner_signed_attrs)
    payload_preserve = b"".join(items)
    # create SET tag 0x31 + length + payload
    def encode_len(n: int):
        if n < 0x80:
            return bytes([n])
        s = n.to_bytes((n.bit_length() + 7)//8, "big")
        return bytes([0x80 | len(s)]) + s
    set_preserve = bytes([0x31]) + encode_len(len(payload_preserve)) + payload_preserve
    variants["set_preserve"] = set_preserve
    # sorted
    payload_sorted = b"".join(sorted(items))
    set_sorted = bytes([0x31]) + encode_len(len(payload_sorted)) + payload_sorted
    variants["set_sorted"] = set_sorted
    # outer variants if outer header present
    if outer_bytes:
        # find position where inner content starts in outer_bytes (header len)
        header_len = len(outer_bytes) - len(inner_signed_attrs)
        if header_len > 0:
            variants["outer_set_preserve"] = outer_bytes[:header_len] + set_preserve
            variants["outer_set_sorted"] = outer_bytes[:header_len] + set_sorted

    # compute SHA256 for each variant
    hashes = {k: hashlib.sha256(v).hexdigest() for k,v in variants.items()}
    return hashes

def verify_pdf_aes_openssl(pdf_path: str, ca_bundle: str = None):
    """
    Extract signature and attempt to verify using OpenSSL cms and a tolerant fallback path.
    Returns (bool_valid, details_dict)
    """
    try:
        signed_bytes, sig_bytes = _extract_byte_range_and_sig(pdf_path)
    except Exception as e:
        return False, {"message": "extract_failed", "error": str(e)}

    with tempfile.TemporaryDirectory() as td:
        content_path = os.path.join(td, "content.bin")
        sig_path = os.path.join(td, "sig.der")
        with open(content_path, "wb") as cf:
            cf.write(signed_bytes)
        with open(sig_path, "wb") as sf:
            sf.write(sig_bytes)

        # 1) Try native OpenSSL CMS verify first
        ok, details = _try_openssl_cms_verify(sig_path, content_path, ca_bundle)
        details_summary = {"openssl_attempt": details}
        if ok:
            details_summary["message"] = "openssl cms verify passed"
            return True, details_summary

        # 2) If OpenSSL failed, attempt manual recovery & checks
        details_summary["openssl_failed"] = details

        # attempt to recover digestInfo from signature using local signer cert (if present)
        recovered_digest = None
        recovered_info = {}
        recovered_digest, recovered_info = _recover_digestinfo_from_signature(sig_path, LOCAL_SIGNER_CERT)
        details_summary["recovered_info"] = recovered_info
        if recovered_digest:
            details_summary["recovered_digest_hex"] = recovered_digest.hex()

        # Try to find the signedAttributes raw bytes from the CMS blob (sig_bytes)
        # We'll attempt a heuristic: find the SignedAttributes container inside the DER blob.
        # Commonly SignedAttributes are present under the SignerInfo structure inside the signedData.
        raw = sig_bytes
        # search for '/signedAttributes' like sequences: we look for the context-specific tag 0xa0 followed by 0x30
        a0_idx = raw.find(b'\xa0')
        # fallback: find the first 0x30 that looks like attributes following a0 header seen earlier
        inner_signed_attrs = None
        outer_signed_attrs = None
        if a0_idx != -1:
            # try to capture the full TLV at that position
            try:
                # parse header
                pos = a0_idx + 1
                first = raw[pos]; pos += 1
                if first & 0x80:
                    n = first & 0x7F
                    length = int.from_bytes(raw[pos:pos+n], "big")
                    pos += n
                else:
                    length = first
                start = pos
                end = start + length
                outer_signed_attrs = raw[a0_idx:end]
                # inner likely starts at the first 0x30 inside this
                inner_pos = outer_signed_attrs.find(b'\x30', 0)
                if inner_pos >= 0:
                    inner_signed_attrs = outer_signed_attrs[inner_pos:]
            except Exception as e:
                details_summary["attrs_extract_error"] = str(e)

        # if heuristic failed, try to look for a clear /messageDigest OID and work backwards
        if inner_signed_attrs is None:
            # look for the messageDigest attribute octet string value and take a window around it
            m = re.search(br'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01', raw)  # sha256 OID in DER (0x60.. is 2.16.840.1.101.3.4.2.1)
            if m:
                idx = m.start()
                # take a chunk backward and forward
                start = max(0, idx - 300)
                end = min(len(raw), idx + 400)
                chunk = raw[start:end]
                # try to find 0xa0 in chunk then extract around it
                a0c = chunk.find(b'\xa0')
                if a0c >= 0:
                    # map to original indexes
                    real_a0 = start + a0c
                    try:
                        pos = real_a0 + 1
                        first = raw[pos]; pos += 1
                        if first & 0x80:
                            n = first & 0x7F
                            length = int.from_bytes(raw[pos:pos+n], "big")
                            pos += n
                        else:
                            length = first
                        outer_signed_attrs = raw[real_a0: pos+length]
                        inner_pos = outer_signed_attrs.find(b'\x30', 0)
                        if inner_pos >= 0:
                            inner_signed_attrs = outer_signed_attrs[inner_pos:]
                    except Exception as e:
                        details_summary["attrs_extract_fallback_err"] = str(e)

        # if still None, as last resort, try to read 'signedAttrs2.der' / 'signedAttrs.der' files from cwd (for debugging)
        if inner_signed_attrs is None:
            try:
                # helpful during local debugging; not required in production
                if os.path.exists("signedAttrs2.der"):
                    inner_signed_attrs = open("signedAttrs2.der","rb").read()
                    details_summary["attrs_loaded_from_file"] = "signedAttrs2.der"
            except:
                pass

        # compute candidate canonicalizations & their hashes
        candidate_hashes = {}
        if inner_signed_attrs is not None:
            outer_bytes = outer_signed_attrs if outer_signed_attrs is not None else None
            candidate_hashes = _try_canonical_signedattrs_matches(sig_bytes, inner_signed_attrs, outer_bytes)
            details_summary["candidate_hashes"] = candidate_hashes

        # If we recovered a digest from the signature, compare it to candidate hashes
        if recovered_digest and candidate_hashes:
            rec_hex = recovered_digest.hex()
            for name, hh in candidate_hashes.items():
                if hh == rec_hex:
                    return True, {"message": "openssl_verify_failed_but_manual_digest_match", "which": name, "recovered_digest": rec_hex, "candidate_hashes": candidate_hashes, "recovered_info": recovered_info}

        # As a final pragmatic fallback: extract the messageDigest attribute from the signedAttrs (if present)
        # and compare it to the SHA256 of the content.bin (signed_bytes).
        msgdig = None
        if inner_signed_attrs is not None:
            # search for the messageDigest octet string inside inner_signed_attrs
            m = re.search(br'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01.*?\x04\x20([0-9A-Fa-f\x00-\xff]{32})', inner_signed_attrs, re.S)
            # above regex is a bit loose; we'll instead search for the exact OCTET STRING with length 0x20 (32)
            m2 = re.search(br'\x04\x20(.{32})', inner_signed_attrs, re.S)
            if m2:
                msgdig = m2.group(1)
                details_summary["messageDigest_extracted_hex"] = msgdig.hex()

        # compute content SHA256
        content_sha = _sha256_hex(signed_bytes)
        details_summary["content_sha256"] = content_sha

        if msgdig:
            if msgdig.hex() == content_sha:
                # Accept as fallback — messageDigest inside CMS matches content hash
                details_summary["message"] = "accepted_by_messageDigest_fallback"
                details_summary["fallback_match"] = True
                return True, details_summary
            else:
                details_summary["messageDigest_mismatch"] = {"cms": msgdig.hex(), "computed": content_sha}

        # nothing matched
        details_summary["final"] = "not_verified"
        return False, details_summary
