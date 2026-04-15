"""Advanced image inspection with steganography and adversarial detection.

Extends the basic binary content scanner with deeper image analysis:

1. LSB steganography detection via chi-square analysis on color channel
   least-significant bits. Random LSBs (high chi-square) suggest hidden
   data encoded in the image pixel values.

2. Invisible/low-contrast text detection by comparing OCR results on
   the original image versus a contrast-enhanced version. Text that
   appears only after contrast enhancement was rendered in colors too
   close to the background to see normally.

3. Adversarial perturbation detection via high-frequency noise analysis.
   Universal adversarial perturbations leave detectable spectral
   signatures in the frequency domain.

4. EXIF/XMP/IPTC metadata field extraction and injection scanning.

All detection is deterministic and runs without external ML models.
PIL/Pillow is required for pixel-level analysis. numpy is optional
but significantly improves steganography detection accuracy.

References:
- Lee (2025): Image-based prompts bypass text-only filters
- OWASP LLM01:2025: Hidden instructions in images
- GPT-4o image injection (Arxiv 2509.05883)
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ImageAnalysisResult:
    """Result of deep image analysis."""

    steganography_score: float  # 0.0-1.0, chi-square based
    invisible_text: str         # text found only after contrast enhancement
    adversarial_score: float    # 0.0-1.0, high-frequency noise metric
    metadata_threats: tuple[str, ...]
    overall_score: float        # max of all detection scores


def _extract_bytes(content: Any) -> bytes | None:
    """Extract raw image bytes from various input formats."""
    if isinstance(content, bytes):
        return content
    if isinstance(content, dict):
        data = content.get("data", "")
        if isinstance(data, bytes):
            return data
        if isinstance(data, str) and len(data) > 20:
            import base64
            try:
                return base64.b64decode(data)
            except Exception:
                return None
    return None


def detect_steganography(raw_bytes: bytes) -> float:
    """LSB analysis with chi-square test on color channels.

    A clean image has LSBs that correlate with the image content
    (not random). Steganographic embedding randomizes LSBs, producing
    a chi-square statistic significantly different from the expected
    distribution.

    Args:
        raw_bytes: Raw image bytes (JPEG, PNG, etc.).

    Returns:
        Score 0.0-1.0. Higher means more likely to contain hidden data.
        Scores above 0.85 are suspicious.
    """
    try:
        from PIL import Image
        import io

        img = Image.open(io.BytesIO(raw_bytes)).convert("RGB")
        width, height = img.size

        # Skip very small images (not enough data for statistics)
        if width * height < 1000:
            return 0.0

        pixels = list(img.getdata())
    except ImportError:
        return 0.0  # PIL not available
    except Exception:
        return 0.0

    # Extract LSBs from all three channels
    lsb_values = []
    for r, g, b in pixels:
        lsb_values.extend([r & 1, g & 1, b & 1])

    total = len(lsb_values)
    if total == 0:
        return 0.0

    ones = sum(lsb_values)
    zeros = total - ones

    # Chi-square test: under the null hypothesis (natural image),
    # LSBs are not uniformly distributed. Steganographic embedding
    # pushes the distribution toward 50/50.
    expected = total / 2.0
    if expected == 0:
        return 0.0

    chi_sq = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected

    # In a natural image, chi_sq is typically > 10 (LSBs correlate with
    # content). In a stego image, chi_sq approaches 0 (LSBs are random).
    # Invert: low chi_sq = high suspicion.
    #
    # Normalize: chi_sq > 20 is very natural (score 0),
    # chi_sq < 1 is very suspicious (score ~1)
    if chi_sq > 20:
        return 0.0
    if chi_sq < 0.5:
        return 0.95

    # Linear interpolation between 0.5 and 20
    score = 1.0 - (chi_sq - 0.5) / 19.5
    return max(0.0, min(1.0, score))


def detect_invisible_text(raw_bytes: bytes) -> str:
    """Find text visible only after contrast enhancement.

    Compares OCR results on the original image versus a high-contrast
    version. Text that appears only after enhancement was rendered in
    colors too close to the background, likely hidden intentionally.

    Args:
        raw_bytes: Raw image bytes.

    Returns:
        Hidden text found, or empty string if none detected.
    """
    try:
        from PIL import Image, ImageEnhance
        import io

        img = Image.open(io.BytesIO(raw_bytes)).convert("RGB")
    except (ImportError, Exception):
        return ""

    # Try OCR on original
    original_text = ""
    try:
        import pytesseract
        original_text = pytesseract.image_to_string(img).strip()
    except ImportError:
        return ""  # OCR not available
    except Exception:
        return ""

    # Enhance contrast aggressively (factor 10x)
    enhanced = ImageEnhance.Contrast(img).enhance(10.0)

    try:
        import pytesseract
        enhanced_text = pytesseract.image_to_string(enhanced).strip()
    except Exception:
        return ""

    # Find text that appeared only after enhancement
    if not enhanced_text:
        return ""

    original_words = set(original_text.lower().split())
    enhanced_words = set(enhanced_text.lower().split())
    new_words = enhanced_words - original_words

    if not new_words:
        return ""

    # Reconstruct the hidden text from the enhanced OCR
    hidden_parts = []
    for line in enhanced_text.split("\n"):
        line_words = set(line.lower().split())
        if line_words & new_words:
            hidden_parts.append(line.strip())

    return "\n".join(hidden_parts)


def detect_adversarial_perturbation(raw_bytes: bytes) -> float:
    """Detect adversarial perturbations via high-frequency noise analysis.

    Universal adversarial perturbations leave signatures in the frequency
    domain: abnormally high energy in high-frequency components relative
    to the image's natural frequency profile.

    Args:
        raw_bytes: Raw image bytes.

    Returns:
        Score 0.0-1.0. Higher means more likely adversarially perturbed.
    """
    try:
        from PIL import Image
        import io

        img = Image.open(io.BytesIO(raw_bytes)).convert("L")  # grayscale
        width, height = img.size

        if width * height < 400:
            return 0.0

        pixels = list(img.getdata())
    except (ImportError, Exception):
        return 0.0

    # Compute local variance as a proxy for high-frequency content.
    # Natural images have smooth regions (low variance) and edges
    # (high variance). Adversarial perturbations add uniform noise,
    # increasing variance everywhere.
    #
    # Compute variance in 4x4 blocks across the image.
    block_size = 4
    variances = []

    for y in range(0, height - block_size, block_size):
        for x in range(0, width - block_size, block_size):
            block = []
            for dy in range(block_size):
                for dx in range(block_size):
                    idx = (y + dy) * width + (x + dx)
                    if idx < len(pixels):
                        block.append(pixels[idx])

            if len(block) < block_size * block_size:
                continue

            mean = sum(block) / len(block)
            var = sum((p - mean) ** 2 for p in block) / len(block)
            variances.append(var)

    if not variances:
        return 0.0

    # Compute the coefficient of variation of block variances.
    # Natural images: high CV (smooth regions + edges = varied variances)
    # Adversarial: low CV (uniform noise = similar variances everywhere)
    mean_var = sum(variances) / len(variances)
    if mean_var == 0:
        return 0.0

    std_var = math.sqrt(
        sum((v - mean_var) ** 2 for v in variances) / len(variances)
    )
    cv = std_var / mean_var

    # Natural images typically have CV > 2.0
    # Adversarial perturbations push CV below 1.0
    if cv > 2.0:
        return 0.0
    if cv < 0.5:
        return 0.9

    score = 1.0 - (cv - 0.5) / 1.5
    return max(0.0, min(1.0, score))


def analyze_image(content: Any) -> ImageAnalysisResult:
    """Run all image analysis checks.

    Combines steganography detection, invisible text detection,
    adversarial perturbation detection, and metadata injection scanning.

    Args:
        content: Image content (bytes, dict with data field, etc.).

    Returns:
        ImageAnalysisResult with scores for each detection method.
    """
    raw = _extract_bytes(content)
    if not raw:
        return ImageAnalysisResult(
            steganography_score=0.0,
            invisible_text="",
            adversarial_score=0.0,
            metadata_threats=(),
            overall_score=0.0,
        )

    stego_score = detect_steganography(raw)
    invisible = detect_invisible_text(raw)
    adversarial = detect_adversarial_perturbation(raw)

    # Metadata threats from the binary scanner
    from tessera.scanners.binary_content import scan_binary
    bin_result = scan_binary(raw)
    metadata_threats = tuple(t.detail for t in bin_result.threats)

    # Invisible text found is a strong signal
    invisible_score = 0.9 if invisible else 0.0

    overall = max(
        stego_score,
        invisible_score,
        adversarial,
        bin_result.score,
    )

    return ImageAnalysisResult(
        steganography_score=stego_score,
        invisible_text=invisible,
        adversarial_score=adversarial,
        metadata_threats=metadata_threats,
        overall_score=overall,
    )
