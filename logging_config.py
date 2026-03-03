"""
SentinelSQL — logging_config.py
Centralized logging configuration for all layers.

Features:
  ✓ Color-coded terminal output (DEBUG=grey, INFO=white, WARNING=yellow, ERROR=red)
  ✓ Simultaneous file + terminal logging
  ✓ Auto-rotating log files (max 5MB per file, keeps last 5 files)
  ✓ Separate files: app.log (everything) + errors.log (errors only)
  ✓ One place to control log level for the entire project
  ✓ Silences noisy third-party libraries

Usage — call once at the very top of main.py BEFORE anything else:

    from logging_config import setup_logging
    setup_logging()

Every other file just does the standard:

    import logging
    logger = logging.getLogger("sentinelsql.auth.routes")
    logger.info("something happened")

Log files are written to:
    C:\\sentinelSQL\\logs\\app.log
    C:\\sentinelSQL\\logs\\errors.log
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path


# ─── CONFIGURATION ────────────────────────────────────────────────────────────
# Change these values to control logging behaviour across the entire project.

# Master log level for SentinelSQL loggers.
# DEBUG   → everything (use during development)
# INFO    → normal operation messages only
# WARNING → only warnings and errors
LOG_LEVEL = logging.DEBUG

# Directory where log files are saved (relative to this file's location)
LOG_DIR = Path(__file__).parent / "logs"

# Log file settings
APP_LOG_FILE    = LOG_DIR / "app.log"       # All logs (DEBUG and above)
ERROR_LOG_FILE  = LOG_DIR / "errors.log"    # Only WARNING / ERROR / CRITICAL

MAX_BYTES       = 5 * 1024 * 1024   # 5 MB per file before rotation
BACKUP_COUNT    = 5                 # Keep last 5 rotated files


# ─── ANSI COLOR CODES (terminal only) ─────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

BLACK   = "\033[30m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
MAGENTA = "\033[35m"
CYAN    = "\033[36m"
WHITE   = "\033[37m"

BRIGHT_RED     = "\033[91m"
BRIGHT_GREEN   = "\033[92m"
BRIGHT_YELLOW  = "\033[93m"
BRIGHT_BLUE    = "\033[94m"
BRIGHT_MAGENTA = "\033[95m"
BRIGHT_CYAN    = "\033[96m"
BRIGHT_WHITE   = "\033[97m"


# ─── LEVEL → COLOR MAPPING ────────────────────────────────────────────────────

LEVEL_COLORS: dict[int, str] = {
    logging.DEBUG:    DIM + WHITE,
    logging.INFO:     BRIGHT_WHITE,
    logging.WARNING:  BRIGHT_YELLOW,
    logging.ERROR:    BRIGHT_RED,
    logging.CRITICAL: BOLD + RED,
}

LEVEL_LABELS: dict[int, str] = {
    logging.DEBUG:    f"{DIM}{WHITE}DEBUG   {RESET}",
    logging.INFO:     f"{BRIGHT_GREEN}INFO    {RESET}",
    logging.WARNING:  f"{BRIGHT_YELLOW}WARNING {RESET}",
    logging.ERROR:    f"{BRIGHT_RED}ERROR   {RESET}",
    logging.CRITICAL: f"{BOLD}{RED}CRITICAL{RESET}",
}

# Logger name → color (so different modules stand out)
LOGGER_COLORS: dict[str, str] = {
    "sentinelsql.main":                     BRIGHT_CYAN,
    "sentinelsql.auth.routes":              BRIGHT_BLUE,
    "sentinelsql.auth.mock_users":          BLUE,
    "sentinelsql.layer01.context_builder":  BRIGHT_MAGENTA,
    "sentinelsql.layer01.session_token":    MAGENTA,
    "sentinelsql.layer01.role_resolver":    BRIGHT_GREEN,
    "sentinelsql.layer01.identity_provider": GREEN,
}


# ─── COLOR FORMATTER (terminal) ───────────────────────────────────────────────

class ColorFormatter(logging.Formatter):
    """
    Formats log records with ANSI colors for terminal output.
    Each module gets its own color so you can visually scan the log.

    Example output:
    12:45:01 | INFO     | sentinelsql.auth.routes        | >>> [LOGIN] dr.arjun attempting login
    """

    # Detect if terminal supports colors (disabled on Windows without ANSI support)
    _colors_supported: bool = (
        hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        or os.environ.get("FORCE_COLOR") == "1"
        or os.environ.get("TERM") in ("xterm", "xterm-256color", "screen", "screen-256color")
    )

    def format(self, record: logging.LogRecord) -> str:
        # Time
        time_str = self.formatTime(record, "%H:%M:%S")

        # Level label (colored or plain)
        if self._colors_supported:
            level_str = LEVEL_LABELS.get(record.levelno, f"{record.levelname:<8}")
        else:
            level_str = f"{record.levelname:<8}"

        # Logger name (truncated + colored)
        name = record.name
        if self._colors_supported:
            name_color = LOGGER_COLORS.get(name, WHITE)
            name_str = f"{name_color}{name:<28}{RESET}"
        else:
            name_str = f"{name:<28}"

        # Message (colored based on level)
        msg = record.getMessage()
        if self._colors_supported:
            msg_color = LEVEL_COLORS.get(record.levelno, "")
            msg_str = f"{msg_color}{msg}{RESET}"
        else:
            msg_str = msg

        # Exception info if present
        if record.exc_info:
            exc = self.formatException(record.exc_info)
            if self._colors_supported:
                msg_str += f"\n{BRIGHT_RED}{exc}{RESET}"
            else:
                msg_str += f"\n{exc}"

        return f"{DIM}{time_str}{RESET} | {level_str} | {name_str} | {msg_str}"


# ─── PLAIN FORMATTER (log files) ──────────────────────────────────────────────

class PlainFormatter(logging.Formatter):
    """
    Clean, no-color formatter for writing to .log files.
    Includes date + time, level, logger name, and message.

    Example output:
    2025-02-26 12:45:01,234 | INFO     | sentinelsql.auth.routes        | >>> [LOGIN] dr.arjun attempting login
    """

    def format(self, record: logging.LogRecord) -> str:
        time_str  = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        level_str = f"{record.levelname:<8}"
        name_str  = f"{record.name:<28}"
        msg       = record.getMessage()

        output = f"{time_str} | {level_str} | {name_str} | {msg}"

        if record.exc_info:
            output += f"\n{self.formatException(record.exc_info)}"

        return output


# ─── SETUP FUNCTION ───────────────────────────────────────────────────────────

def setup_logging(
    log_level: int = LOG_LEVEL,
    log_dir: Path = LOG_DIR,
    enable_file_logging: bool = True,
) -> None:
    """
    Call this ONCE at the very start of main.py before anything else.

    Args:
        log_level:           Logging level for SentinelSQL loggers (default: DEBUG)
        log_dir:             Directory to write .log files into
        enable_file_logging: Set False to disable file output (terminal only)
    """

    # ── Create logs directory ──────────────────────────────────────────────
    if enable_file_logging:
        log_dir.mkdir(parents=True, exist_ok=True)

    # ── Root logger — set to WARNING so third-party libs stay quiet ────────
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)

    # ── Our application logger — set to full DEBUG ─────────────────────────
    app_logger = logging.getLogger("sentinelsql")
    app_logger.setLevel(log_level)
    app_logger.propagate = False   # Don't bubble up to root (avoids duplicates)

    # Clear any existing handlers (important when uvicorn --reload re-imports)
    app_logger.handlers.clear()

    # ── Handler 1: Terminal (stdout) ───────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(ColorFormatter())
    app_logger.addHandler(console_handler)

    if enable_file_logging:
        # ── Handler 2: app.log — all messages DEBUG and above ──────────────
        app_file_handler = logging.handlers.RotatingFileHandler(
            filename=log_dir / "app.log",
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        app_file_handler.setLevel(logging.DEBUG)
        app_file_handler.setFormatter(PlainFormatter())
        app_logger.addHandler(app_file_handler)

        # ── Handler 3: errors.log — WARNING and above only ─────────────────
        error_file_handler = logging.handlers.RotatingFileHandler(
            filename=log_dir / "errors.log",
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        error_file_handler.setLevel(logging.WARNING)
        error_file_handler.setFormatter(PlainFormatter())
        app_logger.addHandler(error_file_handler)

    # ── Silence noisy third-party libraries ───────────────────────────────
    _silence = [
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "uvicorn.lifespan",
        "fastapi",
        "httpx",
        "httpcore",
        "jose",
        "multipart",
        "passlib",
        "starlette",
        "asyncio",
        "watchfiles",
    ]
    for name in _silence:
        logging.getLogger(name).setLevel(logging.WARNING)

    # Keep uvicorn.access at INFO so HTTP requests still show in terminal
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("uvicorn").setLevel(logging.INFO)

    # ── Startup confirmation ───────────────────────────────────────────────
    startup_logger = logging.getLogger("sentinelsql.main")
    startup_logger.debug(">>> [LOGGING] Logging system initialized")
    startup_logger.debug(">>> [LOGGING] Level          = %s", logging.getLevelName(log_level))
    startup_logger.debug(">>> [LOGGING] Terminal       = color output enabled")
    if enable_file_logging:
        startup_logger.debug(">>> [LOGGING] app.log        = %s", log_dir / "app.log")
        startup_logger.debug(">>> [LOGGING] errors.log     = %s", log_dir / "errors.log")
        startup_logger.debug(">>> [LOGGING] Rotation       = %dMB max, %d backups", MAX_BYTES // 1024 // 1024, BACKUP_COUNT)
    else:
        startup_logger.debug(">>> [LOGGING] File logging   = DISABLED (terminal only)")


# ─── CONVENIENCE: change level at runtime ─────────────────────────────────────

def set_level(level: int) -> None:
    """
    Change the log level at runtime without restarting.
    Useful for temporarily increasing verbosity to debug a specific issue.

    Example:
        from logging_config import set_level
        import logging
        set_level(logging.DEBUG)    # turn on full debug
        set_level(logging.INFO)     # back to normal
    """
    logging.getLogger("sentinelsql").setLevel(level)
    logging.getLogger("sentinelsql.main").info(
        ">>> [LOGGING] Log level changed to %s", logging.getLevelName(level)
    )


# ─── CONVENIENCE: get a pre-named logger ──────────────────────────────────────

def get_logger(name: str) -> logging.Logger:
    """
    Shortcut to get a sentinelsql-namespaced logger.

    Instead of:
        logger = logging.getLogger("sentinelsql.auth.routes")

    You can write:
        from logging_config import get_logger
        logger = get_logger("auth.routes")
    """
    return logging.getLogger(f"sentinelsql.{name}")
