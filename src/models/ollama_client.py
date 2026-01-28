"""Ollama client setup and utilities."""

import base64
import httpx
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage

from ..config import get_settings
from ..utils.logger import log_error


def get_text_model() -> ChatOllama:
    """
    Get the configured text model for reasoning.

    Returns:
        ChatOllama instance configured for text generation.
    """
    settings = get_settings()
    return ChatOllama(
        model=settings.ollama_text_model,
        base_url=settings.ollama_base_url,
        temperature=0.1,
        num_ctx=8192,
    )


def get_vision_model() -> ChatOllama:
    """
    Get the configured vision model for screenshot analysis.

    Returns:
        ChatOllama instance configured for vision tasks.
    """
    settings = get_settings()
    return ChatOllama(
        model=settings.ollama_vision_model,
        base_url=settings.ollama_base_url,
        temperature=0.1,
        num_ctx=4096,
    )


async def analyze_screenshot(
    screenshot_b64: str,
    prompt: str,
    context: str = "",
) -> str:
    """
    Send an image to the vision model for analysis.

    Args:
        screenshot_b64: Base64 encoded screenshot image.
        prompt: The prompt describing what to analyze.
        context: Additional context for the analysis.

    Returns:
        The model's analysis of the image.
    """
    settings = get_settings()
    vlm = get_vision_model()

    full_prompt = prompt
    if context:
        full_prompt = f"{context}\n\n{prompt}"

    message = HumanMessage(
        content=[
            {"type": "text", "text": full_prompt},
            {
                "type": "image_url",
                "image_url": {"url": f"data:image/png;base64,{screenshot_b64}"},
            },
        ]
    )

    try:
        response = await vlm.ainvoke([message])
        return response.content
    except Exception as e:
        log_error(f"Vision analysis failed: {e}")
        return f"Error analyzing screenshot: {e}"


def check_ollama_available() -> bool:
    """
    Verify that Ollama is running and required models exist.

    Returns:
        True if Ollama is available and models are present, False otherwise.
    """
    settings = get_settings()

    try:
        # Check if Ollama server is running
        response = httpx.get(f"{settings.ollama_base_url}/api/tags", timeout=10)
        if response.status_code != 200:
            log_error(f"Ollama server returned status {response.status_code}")
            return False

        # Get list of available models
        data = response.json()
        available_models = [model["name"] for model in data.get("models", [])]

        # Check for required models (handle model name variations)
        text_model = settings.ollama_text_model.split(":")[0]
        vision_model = settings.ollama_vision_model.split(":")[0]

        text_model_available = any(
            text_model in model for model in available_models
        )
        vision_model_available = any(
            vision_model in model for model in available_models
        )

        if not text_model_available:
            log_error(
                f"Text model '{settings.ollama_text_model}' not found. "
                f"Available models: {available_models}"
            )
            return False

        if not vision_model_available:
            log_error(
                f"Vision model '{settings.ollama_vision_model}' not found. "
                f"Available models: {available_models}"
            )
            return False

        return True

    except httpx.ConnectError:
        log_error(
            f"Cannot connect to Ollama at {settings.ollama_base_url}. "
            "Is Ollama running?"
        )
        return False
    except Exception as e:
        log_error(f"Error checking Ollama availability: {e}")
        return False


async def test_model_response() -> bool:
    """
    Test that the text model can generate responses.

    Returns:
        True if the model responds successfully, False otherwise.
    """
    try:
        llm = get_text_model()
        response = await llm.ainvoke("Say 'hello' in one word.")
        return bool(response.content)
    except Exception as e:
        log_error(f"Model test failed: {e}")
        return False
