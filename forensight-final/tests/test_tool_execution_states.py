from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

from app.constants import (
    STATUS_SUCCESS,
    STATUS_TOOL_FAILED,
    STATUS_TOOL_TIMEOUT,
    STATUS_TOOL_NOT_INSTALLED,
)
from app.tools.autopsy_runner import run_autopsy
from app.tools.plaso_runner import run_plaso
from app.tools.volatility_runner import run_volatility


def test_autopsy_runner_records_not_installed_when_executable_missing(tmp_path: Path):
    with patch("app.tools.autopsy_runner.find_autopsy", return_value=None):
        result = run_autopsy(str(tmp_path / "evidence.E01"), str(tmp_path / "autopsy"))
        assert result.status == STATUS_TOOL_NOT_INSTALLED
        assert result.available is False
        assert result.executed is False


def test_plaso_runner_records_not_installed_when_executable_missing(tmp_path: Path):
    with patch("app.tools.plaso_runner.find_plaso", return_value=None):
        result = run_plaso(str(tmp_path / "evidence.E01"), str(tmp_path / "plaso"))
        assert result.status == STATUS_TOOL_NOT_INSTALLED
        assert result.available is False
        assert result.executed is False


def test_volatility_runner_records_not_installed_when_executable_missing(tmp_path: Path):
    with patch("app.tools.volatility_runner.find_volatility", return_value=None):
        result = run_volatility(str(tmp_path / "memory.mem"), str(tmp_path / "vol"))
        assert result.status == STATUS_TOOL_NOT_INSTALLED
        assert result.available is False
        assert result.executed is False


def test_plaso_runner_records_timeout(tmp_path: Path):
    with patch("app.tools.plaso_runner.find_plaso", return_value="dummy_psteal"), \
         patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="psteal", timeout=10)):
        result = run_plaso(str(tmp_path / "evidence.E01"), str(tmp_path / "plaso"))
        assert result.status == STATUS_TOOL_TIMEOUT
        assert result.executed is True


def test_autopsy_runner_records_timeout(tmp_path: Path):
    with patch("app.tools.autopsy_runner.find_autopsy", return_value="dummy_autopsy"), \
         patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="autopsy", timeout=10)):
        result = run_autopsy(str(tmp_path / "evidence.E01"), str(tmp_path / "autopsy"))
        assert result.status == STATUS_TOOL_TIMEOUT
        assert result.executed is True


def test_volatility_runner_records_timeout(tmp_path: Path):
    with patch("app.tools.volatility_runner.find_volatility", return_value="dummy_vol"), \
         patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="vol", timeout=10)):
        result = run_volatility(str(tmp_path / "memory.mem"), str(tmp_path / "vol"))
        assert result.status == STATUS_TOOL_TIMEOUT
        assert result.executed is True
