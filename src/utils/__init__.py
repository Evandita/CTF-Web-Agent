"""Utilities module containing logging, flag detection, and HITL helpers."""

from .logger import (
    setup_logging,
    log_action,
    log_observation,
    log_thinking,
    log_flag_found,
    log_error,
    log_state,
)
from .flag_detector import detect_flag, detect_flag_in_page
from .hitl import request_human_input, confirm_action, show_options

__all__ = [
    "setup_logging",
    "log_action",
    "log_observation",
    "log_thinking",
    "log_flag_found",
    "log_error",
    "log_state",
    "detect_flag",
    "detect_flag_in_page",
    "request_human_input",
    "confirm_action",
    "show_options",
]
