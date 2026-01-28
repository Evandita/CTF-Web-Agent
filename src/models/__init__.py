"""Models module containing Ollama client and vision analysis."""

from .ollama_client import get_text_model, get_vision_model, check_ollama_available
from .vision import analyze_ctf_page

__all__ = [
    "get_text_model",
    "get_vision_model",
    "check_ollama_available",
    "analyze_ctf_page",
]
