from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "forensight.json"


class Config:
    def __init__(self, config_dict: dict[str, Any] | None = None):
        self._data = config_dict or {}

    @classmethod
    def load(cls, custom_path: str | Path | None = None) -> Config:
        target = Path(custom_path) if custom_path else Path(os.getenv("FORENSIGHT_CONFIG", str(DEFAULT_CONFIG_PATH)))
        if target.exists():
            try:
                data = json.loads(target.read_text(encoding="utf-8"))
                return cls(data)
            except Exception:
                pass
        return cls()

    def get_tool_executable(self, tool_name: str) -> str | None:
        tools = self._data.get("tools", {})
        tool_cfg = tools.get(tool_name.lower(), {})
        return tool_cfg.get("executable")

    def get_tool_timeout(self, tool_name: str, default: int = 7200) -> int:
        tools = self._data.get("tools", {})
        tool_cfg = tools.get(tool_name.lower(), {})
        return tool_cfg.get("timeout_seconds", default)

    def get_volatility_plugins(self) -> list[str]:
        tools = self._data.get("tools", {})
        vol_cfg = tools.get("volatility3", {})
        return vol_cfg.get("default_plugins", [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.cmdline",
            "windows.netscan",
        ])

    def get_output_base_dir(self, default: str = "cases") -> str:
        pipeline = self._data.get("pipeline", {})
        return pipeline.get("output_base_dir", default)


# Global default configuration instance
config = Config.load()
