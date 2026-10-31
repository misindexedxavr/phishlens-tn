"""PhishLens TN: static phishing page analysis for Tunisian brands."""

__version__ = "1.0.0"

from .errors import PhishLensError  # noqa: E402
from .pipeline import analyze_url, iter_analysis  # noqa: E402

__all__ = ["analyze_url", "iter_analysis", "PhishLensError", "__version__"]
