"""Tests for flag detector utilities."""

import pytest

from src.utils.flag_detector import detect_flag, detect_flag_in_page, search_flag_in_text


class TestDetectFlag:
    """Tests for the detect_flag function."""

    def test_detect_standard_flag(self):
        """Test detection of standard flag{} format."""
        content = "The flag is flag{test_flag_123}"
        assert detect_flag(content) == "flag{test_flag_123}"

    def test_detect_ctf_format(self):
        """Test detection of CTF{} format."""
        content = "Your reward: CTF{another_flag}"
        assert detect_flag(content) == "CTF{another_flag}"

    def test_detect_picoctf_format(self):
        """Test detection of picoCTF{} format."""
        content = "picoCTF{picoformat_flag}"
        assert detect_flag(content) == "picoCTF{picoformat_flag}"

    def test_detect_htb_format(self):
        """Test detection of HTB{} format."""
        content = "Hack The Box: HTB{hackthebox_flag}"
        assert detect_flag(content) == "HTB{hackthebox_flag}"

    def test_no_flag(self):
        """Test when no flag is present."""
        content = "This is just regular text without any flag."
        assert detect_flag(content) is None

    def test_empty_content(self):
        """Test with empty content."""
        assert detect_flag("") is None
        assert detect_flag(None) is None

    def test_multiple_flags_returns_first(self):
        """Test that first flag is returned when multiple are present."""
        content = "flag{first} and flag{second}"
        result = detect_flag(content)
        assert result == "flag{first}"

    def test_case_insensitive(self):
        """Test case insensitive matching."""
        content = "FLAG{UPPERCASE_FLAG}"
        assert detect_flag(content) is not None


class TestDetectFlagInPage:
    """Tests for comprehensive page flag detection."""

    def test_flag_in_html(self):
        """Test flag detection in HTML content."""
        html = "<html><body>flag{in_html}</body></html>"
        assert detect_flag_in_page(html=html) == "flag{in_html}"

    def test_flag_in_cookies(self):
        """Test flag detection in cookies."""
        cookies = [{"name": "session", "value": "flag{in_cookie}"}]
        assert detect_flag_in_page(cookies=cookies) == "flag{in_cookie}"

    def test_flag_in_cookie_name(self):
        """Test flag detection in cookie name."""
        cookies = [{"name": "flag{in_name}", "value": "test"}]
        assert detect_flag_in_page(cookies=cookies) == "flag{in_name}"

    def test_flag_in_local_storage(self):
        """Test flag detection in localStorage."""
        storage = {"secret": "flag{in_storage}"}
        assert detect_flag_in_page(local_storage=storage) == "flag{in_storage}"

    def test_flag_in_console_logs(self):
        """Test flag detection in console logs."""
        logs = ["Error occurred", "flag{in_console}", "Debug info"]
        assert detect_flag_in_page(console_logs=logs) == "flag{in_console}"

    def test_flag_in_network_response(self):
        """Test flag detection in network responses."""
        responses = [
            {"url": "http://example.com/api", "body": '{"flag": "flag{in_response}"}'}
        ]
        assert detect_flag_in_page(network_responses=responses) == "flag{in_response}"

    def test_no_flag_anywhere(self):
        """Test when flag is not present in any source."""
        result = detect_flag_in_page(
            html="<html>normal page</html>",
            cookies=[{"name": "session", "value": "abc123"}],
            local_storage={"key": "value"},
            console_logs=["log message"],
            network_responses=[{"url": "http://test.com", "body": "response"}],
        )
        assert result is None


class TestSearchFlagInText:
    """Tests for finding all flags in text."""

    def test_find_multiple_flags(self):
        """Test finding multiple flags in text."""
        text = "flag{first} some text flag{second} more text CTF{third}"
        flags = search_flag_in_text(text)
        assert len(flags) >= 2
        assert "flag{first}" in flags or "flag{second}" in flags

    def test_deduplicate_flags(self):
        """Test that duplicate flags are removed."""
        text = "flag{same} and again flag{same}"
        flags = search_flag_in_text(text)
        assert flags.count("flag{same}") == 1

    def test_empty_text(self):
        """Test with empty text."""
        assert search_flag_in_text("") == []
        assert search_flag_in_text(None) == []
