"""
core/hash_ledger.py
────────────────────
SHA-256 document fingerprinting + simple Merkle tree ledger.

This is the INTEGRITY LAYER of PaperTrail AI.

What problem does this solve?
──────────────────────────────
A fraudster submits a salary slip for a loan. The bank rejects the loan.
Six months later, the same fraudster submits the SAME document but with
a salary figure changed from ₹30,000 to ₹60,000. Without this ledger,
the bank has no way to know the document was previously submitted and modified.

With this ledger:
  1. Every document gets a SHA-256 hash when first submitted.
  2. The hash is stored in a local JSON ledger file.
  3. On re-submission, the new hash is compared to the stored hash.
  4. If hashes don't match → TAMPERED DOCUMENT FLAG raised instantly.

What is a Merkle Tree?
───────────────────────
A Merkle tree is like a chain of evidence seals.

        Root Hash (H_ab)
       /               \\
   H_a                H_b
  /   \\              /   \\
 H1   H2            H3   H4
 doc1 doc2          doc3 doc4

If doc2 is tampered, H_a changes, which changes Root Hash.
So you only need the Root Hash to verify ALL documents at once.

For our purposes, we build a lightweight flat Merkle tree across
all documents submitted in a session (or across a ledger file).
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Default ledger file path
DEFAULT_LEDGER_PATH = Path(__file__).parent.parent / "reports" / "hash_ledger.json"


# ---
# LEDGER OPERATIONS
# ---

def load_ledger(ledger_path: Path = DEFAULT_LEDGER_PATH) -> dict:
    """Load existing ledger from disk, or return an empty one."""
    if ledger_path.exists():
        with open(ledger_path, "r") as f:
            return json.load(f)
    return {"entries": {}, "merkle_root": None, "total_documents": 0}


def save_ledger(ledger: dict, ledger_path: Path = DEFAULT_LEDGER_PATH):
    """Persist the ledger to disk."""
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with open(ledger_path, "w") as f:
        json.dump(ledger, f, indent=2)


def register_document(
    filepath: str,
    file_hash: str,
    ledger_path: Path = DEFAULT_LEDGER_PATH
) -> dict:
    """
    Register a document's SHA-256 hash into the ledger.

    If the document (by filename) was seen before:
        - Compare new hash vs stored hash
        - If different → HASH_MISMATCH flag (tampered re-submission)
        - If same      → DUPLICATE_SUBMISSION (possibly innocent)

    If the document is new:
        - Store its hash with timestamp

    Returns a dict describing the registration result.
    """
    ledger = load_ledger(ledger_path)
    filename = os.path.basename(filepath)
    now = datetime.now(timezone.utc).isoformat()

    if filename in ledger["entries"]:
        stored = ledger["entries"][filename]
        if stored["sha256"] != file_hash:
            # HASH MISMATCH — document was tampered between submissions
            result = {
                "status":          "HASH_MISMATCH",
                "severity":        "CRITICAL",
                "filename":        filename,
                "stored_hash":     stored["sha256"],
                "new_hash":        file_hash,
                "first_seen":      stored["first_seen"],
                "re_submitted_at": now,
                "detail": (
                    f"Document '{filename}' was previously submitted on {stored['first_seen']}. "
                    f"The SHA-256 hash has CHANGED — document was modified between submissions."
                )
            }
        else:
            # Same hash — duplicate submission (may be innocent re-upload)
            result = {
                "status":          "DUPLICATE_SUBMISSION",
                "severity":        "LOW",
                "filename":        filename,
                "sha256":          file_hash,
                "first_seen":      stored["first_seen"],
                "re_submitted_at": now,
                "detail": (
                    f"Document '{filename}' is an exact duplicate of a previously submitted file "
                    f"(first seen: {stored['first_seen']})."
                )
            }
        # Update re-submission count
        ledger["entries"][filename]["submission_count"] = \
            stored.get("submission_count", 1) + 1
        ledger["entries"][filename]["last_seen"] = now
    else:
        # First time seeing this document
        ledger["entries"][filename] = {
            "sha256":           file_hash,
            "first_seen":       now,
            "last_seen":        now,
            "submission_count": 1,
        }
        result = {
            "status":    "REGISTERED",
            "severity":  "INFO",
            "filename":  filename,
            "sha256":    file_hash,
            "first_seen": now,
            "detail":    f"Document '{filename}' registered for the first time."
        }

    # Recompute Merkle root after any change
    ledger["total_documents"] = len(ledger["entries"])
    ledger["merkle_root"] = compute_merkle_root(
        [e["sha256"] for e in ledger["entries"].values()]
    )
    ledger["last_updated"] = now

    save_ledger(ledger, ledger_path)
    return result


# ---
# MERKLE TREE IMPLEMENTATION
# ---

def _hash_pair(h1: str, h2: str) -> str:
    """Hash two hex strings together (standard Merkle pair hashing)."""
    combined = (h1 + h2).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def compute_merkle_root(hashes: list) -> Optional[str]:
    """
    Compute the Merkle root from a list of SHA-256 hex strings.

    Algorithm:
        1. If only one hash, that IS the root.
        2. If odd count, duplicate the last hash (standard Bitcoin approach).
        3. Pair up hashes and hash each pair → next level.
        4. Repeat until one hash remains.

    The final root hash represents ALL documents in the ledger.
    If any one document is tampered with, the root changes.
    """
    if not hashes:
        return None
    if len(hashes) == 1:
        return hashes[0]

    level = list(hashes)
    while len(level) > 1:
        # Pad to even length by duplicating the last element
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]

    return level[0]


def verify_ledger_integrity(ledger_path: Path = DEFAULT_LEDGER_PATH) -> dict:
    """
    Recompute the Merkle root from all stored hashes and compare
    with the stored root. If they match, the ledger itself is intact.

    Returns: dict with 'intact' (bool) and 'detail' (str)
    """
    ledger = load_ledger(ledger_path)
    stored_root = ledger.get("merkle_root")
    hashes = [e["sha256"] for e in ledger["entries"].values()]
    recomputed_root = compute_merkle_root(hashes)

    if stored_root == recomputed_root:
        return {
            "intact": True,
            "merkle_root": stored_root,
            "detail": "Ledger integrity verified — Merkle root matches all stored hashes."
        }
    else:
        return {
            "intact": False,
            "stored_root":     stored_root,
            "recomputed_root": recomputed_root,
            "detail": "LEDGER TAMPERED — Merkle root mismatch. The ledger file was modified externally!"
        }
