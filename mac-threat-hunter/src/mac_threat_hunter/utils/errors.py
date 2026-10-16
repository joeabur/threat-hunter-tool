"""Exception types with CLI exit-code semantics."""

from __future__ import annotations

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INPUT = 3
EXIT_VALIDATION = 4
EXIT_NO_TELEMETRY = 5


class HunterError(Exception):
    """Base error. ``exit_code`` is used by the CLI."""

    exit_code = EXIT_INPUT


class UsageError(HunterError):
    exit_code = EXIT_USAGE


class InputError(HunterError):
    """Evidence, IOC, baseline or report input could not be read safely."""

    exit_code = EXIT_INPUT


class ValidationError(HunterError):
    """Rules, configuration, IOC or baseline content failed validation."""

    exit_code = EXIT_VALIDATION

    def __init__(self, message: str, problems: list[str] | None = None) -> None:
        super().__init__(message)
        self.problems = problems or []


class PathSafetyError(InputError):
    """A path escaped its allowed base directory or was a disallowed symlink."""
