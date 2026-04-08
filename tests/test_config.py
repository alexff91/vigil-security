"""Tests for configuration loading."""

import os
import pytest
from pathlib import Path

from vigil.config import load_config, _env_substitute


class TestEnvSubstitution:
    def test_simple_var(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "hello")
        assert _env_substitute("${TEST_VAR}") == "hello"

    def test_missing_var(self):
        result = _env_substitute("${DEFINITELY_NOT_SET_12345}")
        assert result == ""

    def test_no_vars(self):
        assert _env_substitute("plain string") == "plain string"

    def test_multiple_vars(self, monkeypatch):
        monkeypatch.setenv("A", "x")
        monkeypatch.setenv("B", "y")
        assert _env_substitute("${A}-${B}") == "x-y"


class TestLoadConfig:
    def test_default_config_when_no_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert config.dependencies.enabled is True
        assert config.telegram.enabled is False

    def test_load_yaml_file(self, tmp_path):
        yaml_file = tmp_path / "vigil.yaml"
        yaml_file.write_text("""
telegram:
  bot_token: "test-token"
  chat_id: "12345"

ssl:
  hosts:
    - example.com
  warn_days: 14
""")
        config = load_config(str(yaml_file))
        assert config.telegram.bot_token == "test-token"
        assert config.telegram.chat_id == "12345"
        assert config.ssl.hosts == ["example.com"]
        assert config.ssl.warn_days == 14

    def test_env_substitution_in_yaml(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MY_TOKEN", "secret-bot-token")
        yaml_file = tmp_path / "vigil.yaml"
        yaml_file.write_text("""
telegram:
  bot_token: "${MY_TOKEN}"
  chat_id: "999"
""")
        config = load_config(str(yaml_file))
        assert config.telegram.bot_token == "secret-bot-token"

    def test_empty_yaml(self, tmp_path):
        yaml_file = tmp_path / "vigil.yaml"
        yaml_file.write_text("")
        config = load_config(str(yaml_file))
        assert config.dependencies.enabled is True
