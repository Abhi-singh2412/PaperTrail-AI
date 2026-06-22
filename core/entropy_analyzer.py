"""
core/entropy_analyzer.py
─────────────────────────
Shannon Entropy Analysis for document forensics.

def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of a byte sequence.
    Returns a float in range [0.0, 8.0].
      0.0 = all bytes are identical (no randomness)
      8.0 = perfectly uniform distribution (maximum randomness)
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ---
# MAIN ANALYZER
# ---

# Entropy thresholds
ENTROPY_HIGH_SUSPICIOUS  = 7.5   # Likely encrypted/compressed hidden content
ENTROPY_VERY_HIGH        = 7.8   # Almost certainly encrypted
CHUNK_SIZE               = 4096  # 4KB chunks for section-level analysis
FLAG_CHUNK_THRESHOLD     = 0.30  # Flag if >30% of chunks have high entropy


def analyze_entropy(filepath: str) -> dict:
    """
    Analyze the entropy profile of a file.

    Returns:
        overall_entropy     : float — entropy of the entire file
        header_entropy      : float — entropy of first 1KB (file header region)
        high_entropy_chunks : int   — number of 4KB blocks with entropy > threshold
        total_chunks        : int   — total number of 4KB blocks analyzed
        suspicious_ratio    : float — fraction of high-entropy blocks
        forensic_flags      : list  — any raised flags
    """
    result = {
        "overall_entropy":      0.0,
        "header_entropy":       0.0,
        "high_entropy_chunks":  0,
        "total_chunks":         0,
        "suspicious_ratio":     0.0,
        "forensic_flags":       []
    }

    try:
        with open(filepath, "rb") as f:
            raw = f.read()

        if not raw:
            return result

        # 1. Overall file entropy
        result["overall_entropy"] = shannon_entropy(raw)

        # 2. Header entropy (first 1KB — should be low for text-based docs)
        result["header_entropy"] = shannon_entropy(raw[:1024])

        # 3. Chunk-level analysis — slide through file in 4KB blocks
        chunks = [raw[i:i + CHUNK_SIZE] for i in range(0, len(raw), CHUNK_SIZE)]
        chunk_entropies = [shannon_entropy(c) for c in chunks]
        high_entropy = [e for e in chunk_entropies if e > ENTROPY_HIGH_SUSPICIOUS]

        result["total_chunks"]        = len(chunks)
        result["high_entropy_chunks"] = len(high_entropy)

        if len(chunks) > 0:
            result["suspicious_ratio"] = round(len(high_entropy) / len(chunks), 3)

        # 4. Forensic flag logic
        _apply_entropy_flags(result, filepath)

    except Exception as e:
        result["error"] = str(e)

    return result


def _apply_entropy_flags(result: dict, filepath: str):
    flags  = result["forensic_flags"]
    ext    = os.path.splitext(filepath)[1].lower()
    ratio  = result["suspicious_ratio"]
    overall = result["overall_entropy"]

    # For images (PNG, JPEG), high entropy is NORMAL — skip chunk flagging
    image_exts = {".jpg", ".jpeg", ".png", ".tiff", ".bmp", ".gif"}
    is_image   = ext in image_exts

    # Rule 1: Very high overall entropy in a non-image text document
    if not is_image and overall > ENTROPY_VERY_HIGH:
        flags.append({
            "severity": "MEDIUM",
            "code":     "HIGH_ENTROPY_OVERALL",
            "detail":   (
                f"Overall file entropy is {overall:.2f}/8.0 — unusually high for a text document. "
                f"May indicate encrypted or compressed hidden content embedded in the file."
            )
        })

    # Rule 2: Many high-entropy chunks in a non-image document
    if not is_image and ratio > FLAG_CHUNK_THRESHOLD and result["total_chunks"] > 4:
        flags.append({
            "severity": "MEDIUM",
            "code":     "HIGH_ENTROPY_SECTION",
            "detail":   (
                f"{result['high_entropy_chunks']} of {result['total_chunks']} file sections "
                f"({ratio*100:.0f}%) have entropy > {ENTROPY_HIGH_SUSPICIOUS} — "
                f"suspicious for a plain document. Possible hidden/encrypted payload."
            )
        })

    # Rule 3: Extremely high entropy header (first 1KB) in a non-image
    if not is_image and result["header_entropy"] > 7.2:
        flags.append({
            "severity": "LOW",
            "code":     "HIGH_ENTROPY_HEADER",
            "detail":   (
                f"File header region has entropy {result['header_entropy']:.2f}/8.0. "
                f"Legitimate PDFs and DOCX files have low-entropy headers. "
                f"May indicate file obfuscation or a non-standard format."
            )
        })
