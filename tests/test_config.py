"""Tests for configuration module."""

import pytest

from src.config import Settings, get_settings, update_settings


class TestSettings:
    """Tests for the Settings class."""

    def test_default_values(self):
        """Test that default values are set correctly."""
        settings = Settings()

        assert settings.ollama_base_url == "http://localhost:11434"
        assert settings.ollama_text_model == "llama3.1"
        assert settings.ollama_vision_model == "llava"
        assert settings.max_iterations == 30
        assert settings.timeout_seconds == 30
        assert settings.headless is False
        assert settings.hitl_enabled is True

    def test_flag_patterns_populated(self):
        """Test that flag patterns are populated."""
        settings = Settings()

        assert len(settings.flag_patterns) > 0
        assert any("flag" in p for p in settings.flag_patterns)
        assert any("CTF" in p for p in settings.flag_patterns)

    def test_custom_values(self):
        """Test creating settings with custom values."""
        settings = Settings(
            ollama_text_model="custom-model",
            max_iterations=50,
            headless=True,
        )

        assert settings.ollama_text_model == "custom-model"
        assert settings.max_iterations == 50
        assert settings.headless is True


class TestGetSettings:
    """Tests for the get_settings function."""

    def test_returns_settings_instance(self):
        """Test that get_settings returns a Settings instance."""
        settings = get_settings()
        assert isinstance(settings, Settings)

    def test_returns_same_instance(self):
        """Test that get_settings returns the same instance."""
        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2


class TestUpdateSettings:
    """Tests for the update_settings function."""

    def test_updates_single_value(self):
        """Test updating a single setting value."""
        original = get_settings()
        original_iterations = original.max_iterations

        updated = update_settings(max_iterations=100)

        assert updated.max_iterations == 100
        # Reset for other tests
        update_settings(max_iterations=original_iterations)

    def test_updates_multiple_values(self):
        """Test updating multiple setting values."""
        updated = update_settings(
            headless=True,
            timeout_seconds=60,
        )

        assert updated.headless is True
        assert updated.timeout_seconds == 60

        # Reset
        update_settings(headless=False, timeout_seconds=30)
