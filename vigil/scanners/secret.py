"""Secret and credential detector."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from vigil.config import SecretScanConfig
from vigil.models import Finding, ScanResult, Severity
from vigil.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Each pattern: (name, regex, severity, recommendation)
SECRET_PATTERNS: list[tuple[str, re.Pattern, Severity, str]] = [
    (
        "AWS Access Key ID",
        re.compile(r"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])"),
        Severity.CRITICAL,
        "Rotate the AWS access key immediately at https://console.aws.amazon.com/iam/",
    ),
    (
        "AWS Secret Access Key",
        re.compile(r"""(?:aws_secret_access_key|secret_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""", re.IGNORECASE),
        Severity.CRITICAL,
        "Rotate the AWS secret key immediately and use environment variables or AWS Secrets Manager",
    ),
    (
        "GitHub Personal Access Token",
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        Severity.CRITICAL,
        "Revoke the token at https://github.com/settings/tokens and generate a new one",
    ),
    (
        "GitHub OAuth Access Token",
        re.compile(r"gho_[A-Za-z0-9]{36}"),
        Severity.HIGH,
        "Revoke the OAuth token in GitHub settings",
    ),
    (
        "GitHub Fine-grained PAT",
        re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
        Severity.CRITICAL,
        "Revoke the fine-grained PAT at https://github.com/settings/tokens",
    ),
    (
        "Telegram Bot Token",
        re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"),
        Severity.HIGH,
        "Revoke the token via @BotFather on Telegram and regenerate",
    ),
    (
        "Slack Bot Token",
        re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}"),
        Severity.HIGH,
        "Rotate the Slack bot token in your Slack app settings",
    ),
    (
        "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        Severity.MEDIUM,
        "Regenerate the Slack webhook URL",
    ),
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        Severity.HIGH,
        "Restrict or rotate the Google API key at https://console.cloud.google.com/apis/credentials",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        Severity.CRITICAL,
        "Roll the Stripe key at https://dashboard.stripe.com/apikeys",
    ),
    (
        "Stripe Publishable Key (Live)",
        re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
        Severity.MEDIUM,
        "Consider restricting the Stripe publishable key",
    ),
    (
        "Heroku API Key",
        re.compile(r"[hH]eroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
        Severity.HIGH,
        "Regenerate the Heroku API key",
    ),
    (
        "Generic Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "Remove the private key from the repository and rotate it",
    ),
    (
        "Generic Password in Config",
        re.compile(r"""(?:password|passwd|pwd|secret|token|api_key|apikey|access_key)\s*[=:]\s*['"][^'"]{8,}['"]""", re.IGNORECASE),
        Severity.HIGH,
        "Move the credential to an environment variable or secrets manager",
    ),
    (
        "Database Connection String",
        re.compile(r"(?:mongodb|postgres|mysql|redis|amqp)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"),
        Severity.CRITICAL,
        "Remove database credentials from code. Use environment variables.",
    ),
    (
        "SendGrid API Key",
        re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        Severity.HIGH,
        "Rotate the SendGrid API key",
    ),
    (
        "Twilio Account SID",
        re.compile(r"AC[a-f0-9]{32}"),
        Severity.MEDIUM,
        "Verify this Twilio Account SID should be in the codebase",
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        Severity.MEDIUM,
        "Remove hardcoded JWT tokens. They should be generated at runtime.",
    ),
    (
        "OpenAI API Key",
        re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"),
        Severity.CRITICAL,
        "Rotate the OpenAI API key at https://platform.openai.com/api-keys",
    ),
]

# File extensions to skip (binary/media)
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".exe", ".dll", ".so", ".dylib", ".wasm",
    ".ttf", ".woff", ".woff2", ".eot", ".otf",
    ".pyc", ".pyo", ".class", ".o",
    ".sqlite", ".db", ".sqlite3",
}


class SecretScanner(BaseScanner):
    """Scan files for leaked secrets and credentials."""

    name = "secret"

    def __init__(self, config: SecretScanConfig) -> None:
        self.config = config
        self._compile_excludes()

    def _compile_excludes(self) -> None:
        """Pre-compile exclude patterns into a usable format."""
        self.exclude_dirs = set()
        self.exclude_globs = []
        for pattern in self.config.exclude_patterns:
            if not pattern.startswith("*"):
                self.exclude_dirs.add(pattern)
            else:
                self.exclude_globs.append(pattern)

    async def scan(self) -> ScanResult:
        result = self._make_result()

        if not self.config.enabled:
            return self._finish_result(result)

        paths = self.config.paths or ["."]

        for scan_path in paths:
            p = Path(scan_path).resolve()
            if p.is_file():
                self._scan_file(p, result)
            elif p.is_dir():
                self._scan_directory(p, result)
            else:
                logger.warning("Path does not exist: %s", scan_path)

        return self._finish_result(result)

    def _scan_directory(self, directory: Path, result: ScanResult) -> None:
        """Recursively scan a directory for secrets."""
        for file_path in directory.rglob("*"):
            if not file_path.is_file():
                continue

            # Skip excluded directories
            if any(exc in file_path.parts for exc in self.exclude_dirs):
                continue

            # Skip binary files
            if file_path.suffix.lower() in BINARY_EXTENSIONS:
                continue

            # Skip files matching exclude globs
            if any(file_path.match(glob) for glob in self.exclude_globs):
                continue

            # Skip large files
            try:
                size_kb = file_path.stat().st_size / 1024
                if size_kb > self.config.max_file_size_kb:
                    continue
            except OSError:
                continue

            self._scan_file(file_path, result)

    def _scan_file(self, file_path: Path, result: ScanResult) -> None:
        """Scan a single file for secret patterns."""
        try:
            content = file_path.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            return

        for line_num, line in enumerate(content.splitlines(), start=1):
            for pattern_name, regex, severity, recommendation in SECRET_PATTERNS:
                matches = regex.findall(line)
                if matches:
                    # Redact the actual secret in the finding
                    matched_text = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    redacted = self._redact(matched_text)

                    result.findings.append(Finding(
                        scanner=self.name,
                        severity=severity,
                        title=f"{pattern_name} detected",
                        description=f"Potential {pattern_name} found at line {line_num}: {redacted}",
                        file_path=str(file_path),
                        line_number=line_num,
                        recommendation=recommendation,
                        metadata={
                            "pattern": pattern_name,
                            "redacted_match": redacted,
                        },
                    ))

    @staticmethod
    def _redact(secret: str) -> str:
        """Redact a secret, keeping first 4 and last 4 characters."""
        if len(secret) <= 12:
            return secret[:3] + "****" + secret[-2:]
        return secret[:4] + "****" + secret[-4:]
