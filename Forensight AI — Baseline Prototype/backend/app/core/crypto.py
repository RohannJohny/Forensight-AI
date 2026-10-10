"""
Forensight AI - Cryptographic Engine
Implements:
1. Standard forensic hashing (SHA-256, SHA-1, MD5) for evidence integrity.
2. Two-Key Security Architecture (Module 7):
   - Unique per-report Report Encryption Key (REK, 256-bit)
   - AES-256-GCM authenticated report encryption
   - Master Key (MK, 256-bit) wrapping of REK
   - Plaintext SHA-256 hash verification for tamper detection
"""

import os
import hashlib
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import MASTER_KEY_HEX


def compute_file_hashes(file_bytes: bytes) -> Dict[str, str]:
    """Computes standard forensic hashes for evidence integrity validation."""
    return {
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "byte_size": str(len(file_bytes))
    }


def compute_text_hash(text: str) -> str:
    """Computes SHA-256 hash of UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def get_master_key() -> bytes:
    """Returns the 32-byte (256-bit) system Master Key (MK)."""
    return bytes.fromhex(MASTER_KEY_HEX)


def generate_rek() -> bytes:
    """Generates a random 256-bit Report Encryption Key (REK)."""
    return AESGCM.generate_key(bit_length=256)


def wrap_rek(rek: bytes, master_key: bytes) -> bytes:
    """
    Encrypts the Report Encryption Key (REK) using the Master Key (MK) via AES-256-GCM.
    Returns nonce + ciphertext + auth_tag as single byte payload.
    """
    aesgcm_mk = AESGCM(master_key)
    nonce = os.urandom(12)
    encrypted_rek = aesgcm_mk.encrypt(nonce, rek, associated_data=b"forensight-rek-wrapping")
    return nonce + encrypted_rek


def unwrap_rek(wrapped_payload: bytes, master_key: bytes) -> bytes:
    """Decrypts the wrapped REK using the Master Key (MK)."""
    nonce = wrapped_payload[:12]
    ciphertext = wrapped_payload[12:]
    aesgcm_mk = AESGCM(master_key)
    return aesgcm_mk.decrypt(nonce, ciphertext, associated_data=b"forensight-rek-wrapping")


def encrypt_report_payload(plaintext: str) -> Tuple[bytes, bytes, str]:
    """
    Two-Key Report Encryption Pipeline:
    1. Compute SHA-256 plaintext hash.
    2. Generate unique REK (256-bit).
    3. Encrypt report plaintext with REK using AES-256-GCM.
    4. Encrypt REK with system Master Key (MK).
    Returns: (encrypted_report_payload, wrapped_rek, plaintext_sha256)
    """
    plaintext_bytes = plaintext.encode("utf-8")
    integrity_hash = hashlib.sha256(plaintext_bytes).hexdigest()

    rek = generate_rek()
    aesgcm_rek = AESGCM(rek)
    nonce = os.urandom(12)
    ciphertext = aesgcm_rek.encrypt(nonce, plaintext_bytes, associated_data=b"forensight-report-gcm")
    report_payload = nonce + ciphertext

    master_key = get_master_key()
    wrapped_rek = wrap_rek(rek, master_key)

    return report_payload, wrapped_rek, integrity_hash


def decrypt_report_payload(report_payload: bytes, wrapped_rek: bytes, expected_hash: str) -> Tuple[str, bool]:
    """
    Decrypts encrypted report payload using wrapped REK and Master Key.
    Verifies plaintext SHA-256 integrity hash.
    Returns: (decrypted_text, is_tamper_free)
    """
    master_key = get_master_key()
    rek = unwrap_rek(wrapped_rek, master_key)

    nonce = report_payload[:12]
    ciphertext = report_payload[12:]

    aesgcm_rek = AESGCM(rek)
    decrypted_bytes = aesgcm_rek.decrypt(nonce, ciphertext, associated_data=b"forensight-report-gcm")
    decrypted_text = decrypted_bytes.decode("utf-8")

    computed_hash = hashlib.sha256(decrypted_bytes).hexdigest()
    is_tamper_free = (computed_hash == expected_hash)

    return decrypted_text, is_tamper_free
