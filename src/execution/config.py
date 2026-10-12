"""
Controlled Execution Configuration Module.

Loads and validates configuration for the controlled execution policy
from the main configuration file (config/config.json).
"""

import json
import logging
import os
from typing import Any, Dict, Optional


DEFAULT_CONTROLLED_EXECUTION_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "dry_run": True,
    "score_threshold": 7,
    "blocked_severities": ["HIGH"],
    "blocked_indicators": [],
    "fail_closed": True,
    "launcher": {
        "allow_active_execution": False,
        "default_timeout_seconds": 30,
        "max_output_bytes": 65536,
        "allowed_working_directories": [],
    },
}


def load_execution_config(config_path: str = "config/config.json") -> Dict[str, Any]:
    """
    Load controlled execution configuration from JSON file,
    falling back to DEFAULT_CONTROLLED_EXECUTION_CONFIG.
    """
    config = {
        "enabled": DEFAULT_CONTROLLED_EXECUTION_CONFIG["enabled"],
        "dry_run": DEFAULT_CONTROLLED_EXECUTION_CONFIG["dry_run"],
        "score_threshold": DEFAULT_CONTROLLED_EXECUTION_CONFIG["score_threshold"],
        "blocked_severities": list(DEFAULT_CONTROLLED_EXECUTION_CONFIG["blocked_severities"]),
        "blocked_indicators": list(DEFAULT_CONTROLLED_EXECUTION_CONFIG["blocked_indicators"]),
        "fail_closed": DEFAULT_CONTROLLED_EXECUTION_CONFIG["fail_closed"],
        "launcher": {
            "allow_active_execution": DEFAULT_CONTROLLED_EXECUTION_CONFIG["launcher"]["allow_active_execution"],
            "default_timeout_seconds": DEFAULT_CONTROLLED_EXECUTION_CONFIG["launcher"]["default_timeout_seconds"],
            "max_output_bytes": DEFAULT_CONTROLLED_EXECUTION_CONFIG["launcher"]["max_output_bytes"],
            "allowed_working_directories": list(
                DEFAULT_CONTROLLED_EXECUTION_CONFIG["launcher"]["allowed_working_directories"]
            ),
        },
    }

    if not os.path.exists(config_path):
        return config

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return config
            data = json.loads(content)
            ce_config = data.get("controlled_execution", {})

            if "enabled" in ce_config:
                config["enabled"] = bool(ce_config["enabled"])
            if "dry_run" in ce_config:
                val = ce_config["dry_run"]
                config["dry_run"] = val if isinstance(val, bool) else True
            if "score_threshold" in ce_config:
                config["score_threshold"] = int(ce_config["score_threshold"])
            if "blocked_severities" in ce_config:
                config["blocked_severities"] = list(ce_config["blocked_severities"])
            if "blocked_indicators" in ce_config:
                config["blocked_indicators"] = list(ce_config["blocked_indicators"])
            if "fail_closed" in ce_config:
                config["fail_closed"] = bool(ce_config["fail_closed"])

            launcher_cfg = ce_config.get("launcher", {})
            if isinstance(launcher_cfg, dict):
                if "allow_active_execution" in launcher_cfg:
                    val = launcher_cfg["allow_active_execution"]
                    config["launcher"]["allow_active_execution"] = val if isinstance(val, bool) else False
                if "default_timeout_seconds" in launcher_cfg:
                    val = launcher_cfg["default_timeout_seconds"]
                    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
                        config["launcher"]["default_timeout_seconds"] = float(val)
                if "max_output_bytes" in launcher_cfg:
                    val = launcher_cfg["max_output_bytes"]
                    if isinstance(val, int) and not isinstance(val, bool) and val > 0:
                        config["launcher"]["max_output_bytes"] = int(val)
                if "allowed_working_directories" in launcher_cfg:
                    val = launcher_cfg["allowed_working_directories"]
                    if isinstance(val, list):
                        config["launcher"]["allowed_working_directories"] = [
                            str(p) for p in val if isinstance(p, str)
                        ]

    except Exception as e:
        logging.getLogger("endpoint_monitor").debug(
            f"Could not load controlled_execution config from {config_path}: {e}"
        )

    return config
