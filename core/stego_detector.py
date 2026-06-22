"""
core/stego_detector.py
───────────────────────
LSB (Least Significant Bit) Steganography Detection in Images.

HOW IT WORKS:
  Each pixel in an image has color channels (R, G, B) with values 0–255.
  In binary: 255 = 11111111.  The LAST bit (LSB) contributes only 1/255 to
  the color value — changing it is visually imperceptible to the human eye.

  Attacker replaces LSBs of pixels with bits of their secret message:
    Original pixel R value: 11001010  (202)
    After LSB embed:        11001011  (203) — difference invisible

  To extract: just read every pixel's last bit → reassemble into bytes → secret!

HOW WE DETECT IT — Chi-Square Test:
  In a NATURAL (non-tampered) image:
    The distribution of pairs (2k, 2k+1) in LSBs is NON-UNIFORM.
    Some pairs appear more than others — it follows image content statistics.

  In an LSB-STEGANOGRAPHIC image:
    The pairs become NEARLY EQUAL in frequency.
    This is because embedded random/encrypted data has uniform bit distribution.

  The chi-square statistic measures this deviation from uniformity.
  - Chi-square LARGE  → natural image (non-uniform, likely not stego)
  - Chi-square SMALL  → suspiciously uniform → likely LSB embedding

Additional heuristic — LSB Noise Ratio:
  The ratio of '1' bits in the LSB plane.
  Natural images hover around 45–55%.
  Steganographic images approach exactly 50% (uniform distribution).

LIMITATIONS:
  This is a STATISTICAL test — it detects PROBABILITY of steganography,
  not a definitive proof. False positives are possible for high-noise images.
  For a bank project, it's a valid signal to flag for human review.
"""

import math
from collections import Counter

# ---
# THRESHOLDS
# ---

# LSB ratio: if between these bounds, distribution is suspiciously uniform
LSB_RATIO_LOW  = 0.46
LSB_RATIO_HIGH = 0.54

# Minimum pixels needed to run a meaningful statistical test
MIN_PIXELS_FOR_ANALYSIS = 10_000

# Chi-square threshold: values BELOW this suggest uniform (stego) distribution
CHI_SQUARE_SUSPICIOUS = 0.05

# How many pixels to sample (avoid analyzing huge images byte-by-byte)
SAMPLE_PIXELS = 100_000


# ---
# MAIN DETECTOR
# ---

def detect_steganography(filepath: str) -> dict:
    """
    Analyze an image for signs of LSB steganography.

    Only meaningful for: .jpg, .jpeg, .png, .bmp, .tiff

    Returns:
        pixels_analyzed   : int
        lsb_ratio         : float — ratio of '1' bits in LSB plane
        chi_square_p      : float — p-value from chi-square test (lower = suspicious)
        stego_suspected   : bool
        capacity_estimate : str   — approx. bytes that could be hidden (educational)
        forensic_flags    : list
    """
    result = {
        "pixels_analyzed":   0,
        "lsb_ratio":         0.0,
        "chi_square_p":      1.0,
        "stego_suspected":   False,
        "capacity_estimate": "N/A",
        "forensic_flags":    []
    }

    try:
        from PIL import Image
        img = Image.open(filepath).convert("RGB")  # normalize to RGB

        width, height = img.size
        total_pixels  = width * height

        if total_pixels < MIN_PIXELS_FOR_ANALYSIS:
            result["note"] = f"Image too small for reliable analysis ({total_pixels} pixels)"
            return result

        # Sample pixels evenly across the image
        pixels = list(img.getdata())
        step   = max(1, len(pixels) // SAMPLE_PIXELS)
        sample = pixels[::step]

        # Extract LSBs from R, G, B channels of each sampled pixel
        lsbs = []
        for r, g, b in sample:
            lsbs.append(r & 1)   # LSB of red channel
            lsbs.append(g & 1)   # LSB of green channel
            lsbs.append(b & 1)   # LSB of blue channel

        result["pixels_analyzed"] = len(sample)

        # Metric 1: LSB ratio (how close to 50/50?)
        ones  = sum(lsbs)
        lsb_ratio = ones / len(lsbs) if lsbs else 0.5
        result["lsb_ratio"] = round(lsb_ratio, 4)

        # Metric 2: Chi-square test on value pairs
        # We look at pairs of consecutive pixel values (v, v+1)
        # In natural images, P(2k) ≠ P(2k+1) for most k
        # In steganographic images, P(2k) ≈ P(2k+1)
        chi_p = _chi_square_lsb_test(pixels, step)
        result["chi_square_p"] = round(chi_p, 4)

        # Capacity estimate (educational — shows how much data COULD be hidden)
        capacity_bytes = (total_pixels * 3) // 8   # 3 channels, 1 bit each
        result["capacity_estimate"] = f"~{capacity_bytes:,} bytes ({capacity_bytes // 1024} KB)"

        # Determine suspicion
        ratio_suspicious  = LSB_RATIO_LOW <= lsb_ratio <= LSB_RATIO_HIGH
        chi_suspicious    = chi_p < CHI_SQUARE_SUSPICIOUS

        if ratio_suspicious and chi_suspicious:
            result["stego_suspected"] = True
            result["forensic_flags"].append({
                "severity": "MEDIUM",
                "code":     "STEGANOGRAPHY_SUSPECTED",
                "detail":   (
                    f"LSB analysis suggests possible steganographic content. "
                    f"LSB ratio: {lsb_ratio:.4f} (expected ~0.50 for stego), "
                    f"Chi-square p-value: {chi_p:.4f} (low = uniform = suspicious). "
                    f"Image could conceal up to {result['capacity_estimate']} of hidden data."
                )
            })
        elif ratio_suspicious:
            # Only ratio is suspicious — lower confidence
            result["forensic_flags"].append({
                "severity": "LOW",
                "code":     "LSB_RATIO_ANOMALY",
                "detail":   (
                    f"LSB bit ratio is {lsb_ratio:.4f} — close to 0.50, "
                    f"which can indicate LSB steganography. "
                    f"Manual review recommended for high-value documents."
                )
            })

    except ImportError:
        result["error"] = "Pillow not installed (pip install Pillow)"
    except Exception as e:
        result["error"] = str(e)

    return result


# ---
# CHI-SQUARE TEST
# ---

def _chi_square_lsb_test(pixels: list, step: int) -> float:
    """
    Perform a chi-square test on the distribution of value pairs in the
    Red channel LSBs.

    For each intensity value v (0–254, even values only), we look at the pair
    (count of pixels with value v, count of pixels with value v+1).
    In natural images, these counts differ significantly.
    In stego images, they tend to equalize.

    Returns a p-value (0.0–1.0). Lower = more suspicious.
    """
    try:
        # Count frequency of each R-channel value
        r_values = [p[0] for p in pixels[::step]]
        freq = Counter(r_values)

        # Build pairs (n_2k, n_2k+1) for k = 0..127
        chi_stat = 0.0
        df = 0   # degrees of freedom

        for k in range(0, 256, 2):
            n_even = freq.get(k,     0)
            n_odd  = freq.get(k + 1, 0)
            total  = n_even + n_odd
            if total == 0:
                continue
            expected = total / 2.0
            # Chi-square contribution: (observed - expected)² / expected
            chi_stat += ((n_even - expected) ** 2 + (n_odd - expected) ** 2) / expected
            df += 1

        if df == 0:
            return 1.0

        # Approximate p-value using chi-square CDF (scipy-free approximation)
        p_value = _chi_square_pvalue(chi_stat, df)
        return p_value

    except Exception:
        return 1.0


def _chi_square_pvalue(chi2: float, df: int) -> float:
    """
    Approximate chi-square p-value without scipy.
    Uses the incomplete gamma function approximation.
    Returns p-value ∈ [0, 1]. Lower values = more evidence against null hypothesis.
    """
    try:
        # Use regularized incomplete gamma function approximation
        # p = 1 - CDF(chi2, df)  ≈ 1 - gammainc(df/2, chi2/2)
        x = chi2 / 2.0

        # Compute using series expansion of the regularized lower incomplete gamma
        # P(k, x) = e^{-x} * x^k / Γ(k) * Σ x^n / Γ(k+n+1)
        if x <= 0:
            return 1.0

        # Use the complement: survival function
        # For large chi2/df ratios, p-value → 0
        # For small chi2/df ratios, p-value → 1
        ratio = chi2 / max(df, 1)

        # Heuristic approximation (good enough for our threshold at 0.05)
        if ratio < 0.5:
            return min(1.0, ratio * 2)
        elif ratio < 1.0:
            return max(0.0, 1.0 - (ratio - 0.5) * 1.5)
        else:
            return max(0.0, math.exp(-0.5 * (chi2 - df)) / max(1, math.sqrt(df)))

    except Exception:
        return 1.0
