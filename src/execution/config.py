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
    "interception_enabled": False,
    "score_threshold": 7,
    "block_threshold": 7,
    "approval_threshold": 4,
    "blocked_severities": ["HIGH"],
    "blocked_indicators": [],
    "fail_closed": True,
    "launcher": {
        "allow_active_execution": False,
        "default_timeout_seconds": 30,
        "max_output_bytes": 65536,
        "allowed_working_directories": [],
    },
    "windows_enforcement": {
        "enabled": False,
        "channels": [
            "Microsoft-Windows-CodeIntegrity/Operational",
            "Microsoft-Windows-AppLocker/EXE and DLL",
        ],
        "poll_interval_seconds": 5.0,
        "max_events_per_query": 50,
        "correlate_with_processes": True,
        "alert_on_blocks": True,
    },
    "windows_process_telemetry": {
        "enabled": False,
        "channel": "Security",
        "event_id": 4688,
        "max_events_per_query": 200,
        "query_timeout_seconds": 10.0,
        "dedup_tolerance_seconds": 5.0,
        "require_command_line": False,
    },
    "sysmon_telemetry": {
        "enabled": False,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "enable_process_events": True,
        "enable_network_events": True,
        "max_events_per_query": 200,
        "query_timeout_seconds": 10.0,
        "dedup_tolerance_seconds": 5.0,
    },
    "firewall_enforcement": {
        "enabled": False,
        "dry_run": True,
        "auto_block_suspicious": False,
        "block_threshold": 7,
        "blocked_severities": ["HIGH"],
        "blocked_indicators": [],
        "allowed_executables": [],
        "rule_prefix": "EndpointMonitor_Block_",
        "rule_group": "Endpoint Monitor Enforcement",
        "timeout_seconds": 10.0,
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
        "interception_enabled": DEFAULT_CONTROLLED_EXECUTION_CONFIG["interception_enabled"],
        "score_threshold": DEFAULT_CONTROLLED_EXECUTION_CONFIG["score_threshold"],
        "block_threshold": DEFAULT_CONTROLLED_EXECUTION_CONFIG["block_threshold"],
        "approval_threshold": DEFAULT_CONTROLLED_EXECUTION_CONFIG["approval_threshold"],
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
        "windows_enforcement": {
            "enabled": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_enforcement"]["enabled"],
            "channels": list(DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_enforcement"]["channels"]),
            "poll_interval_seconds": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_enforcement"]["poll_interval_seconds"],
            "max_events_per_query": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_enforcement"]["max_events_per_query"],
            "correlate_with_processes": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_enforcement"]["correlate_with_processes"],
            "alert_on_blocks": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_enforcement"]["alert_on_blocks"],
        },
        "windows_process_telemetry": {
            "enabled": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_process_telemetry"]["enabled"],
            "channel": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_process_telemetry"]["channel"],
            "event_id": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_process_telemetry"]["event_id"],
            "max_events_per_query": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_process_telemetry"]["max_events_per_query"],
            "query_timeout_seconds": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_process_telemetry"]["query_timeout_seconds"],
            "dedup_tolerance_seconds": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_process_telemetry"]["dedup_tolerance_seconds"],
            "require_command_line": DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_process_telemetry"]["require_command_line"],
        },
        "sysmon_telemetry": {
            "enabled": DEFAULT_CONTROLLED_EXECUTION_CONFIG["sysmon_telemetry"]["enabled"],
            "channel": DEFAULT_CONTROLLED_EXECUTION_CONFIG["sysmon_telemetry"]["channel"],
            "enable_process_events": DEFAULT_CONTROLLED_EXECUTION_CONFIG["sysmon_telemetry"]["enable_process_events"],
            "enable_network_events": DEFAULT_CONTROLLED_EXECUTION_CONFIG["sysmon_telemetry"]["enable_network_events"],
            "max_events_per_query": DEFAULT_CONTROLLED_EXECUTION_CONFIG["sysmon_telemetry"]["max_events_per_query"],
            "query_timeout_seconds": DEFAULT_CONTROLLED_EXECUTION_CONFIG["sysmon_telemetry"]["query_timeout_seconds"],
            "dedup_tolerance_seconds": DEFAULT_CONTROLLED_EXECUTION_CONFIG["sysmon_telemetry"]["dedup_tolerance_seconds"],
        },
        "firewall_enforcement": {
            "enabled": DEFAULT_CONTROLLED_EXECUTION_CONFIG["firewall_enforcement"]["enabled"],
            "dry_run": DEFAULT_CONTROLLED_EXECUTION_CONFIG["firewall_enforcement"]["dry_run"],
            "auto_block_suspicious": DEFAULT_CONTROLLED_EXECUTION_CONFIG["firewall_enforcement"]["auto_block_suspicious"],
            "block_threshold": DEFAULT_CONTROLLED_EXECUTION_CONFIG["firewall_enforcement"]["block_threshold"],
            "blocked_severities": list(DEFAULT_CONTROLLED_EXECUTION_CONFIG["firewall_enforcement"]["blocked_severities"]),
            "blocked_indicators": list(DEFAULT_CONTROLLED_EXECUTION_CONFIG["firewall_enforcement"]["blocked_indicators"]),
            "allowed_executables": list(DEFAULT_CONTROLLED_EXECUTION_CONFIG["firewall_enforcement"]["allowed_executables"]),
            "rule_prefix": DEFAULT_CONTROLLED_EXECUTION_CONFIG["firewall_enforcement"]["rule_prefix"],
            "rule_group": DEFAULT_CONTROLLED_EXECUTION_CONFIG["firewall_enforcement"]["rule_group"],
            "timeout_seconds": DEFAULT_CONTROLLED_EXECUTION_CONFIG["firewall_enforcement"]["timeout_seconds"],
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
            if "interception_enabled" in ce_config:
                val = ce_config["interception_enabled"]
                config["interception_enabled"] = val if isinstance(val, bool) else False
            if "score_threshold" in ce_config:
                config["score_threshold"] = int(ce_config["score_threshold"])
                config["block_threshold"] = int(ce_config["score_threshold"])
            if "block_threshold" in ce_config:
                config["block_threshold"] = int(ce_config["block_threshold"])
                config["score_threshold"] = int(ce_config["block_threshold"])
            if "approval_threshold" in ce_config:
                config["approval_threshold"] = int(ce_config["approval_threshold"])
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

            we_cfg = ce_config.get("windows_enforcement", {})
            if isinstance(we_cfg, dict):
                if "enabled" in we_cfg:
                    config["windows_enforcement"]["enabled"] = bool(we_cfg["enabled"])
                if "channels" in we_cfg and isinstance(we_cfg["channels"], list):
                    config["windows_enforcement"]["channels"] = [
                        str(c) for c in we_cfg["channels"] if isinstance(c, str)
                    ]
                if "poll_interval_seconds" in we_cfg:
                    val = we_cfg["poll_interval_seconds"]
                    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
                        config["windows_enforcement"]["poll_interval_seconds"] = float(val)
                if "max_events_per_query" in we_cfg:
                    val = we_cfg["max_events_per_query"]
                    if isinstance(val, int) and not isinstance(val, bool) and val > 0:
                        config["windows_enforcement"]["max_events_per_query"] = int(val)
                if "correlate_with_processes" in we_cfg:
                    config["windows_enforcement"]["correlate_with_processes"] = bool(
                        we_cfg["correlate_with_processes"]
                    )
                if "alert_on_blocks" in we_cfg:
                    config["windows_enforcement"]["alert_on_blocks"] = bool(
                        we_cfg["alert_on_blocks"]
                    )

            wpt_cfg = ce_config.get("windows_process_telemetry", {})
            if isinstance(wpt_cfg, dict):
                if "enabled" in wpt_cfg:
                    config["windows_process_telemetry"]["enabled"] = bool(wpt_cfg["enabled"])
                if "channel" in wpt_cfg and isinstance(wpt_cfg["channel"], str):
                    channel_name = wpt_cfg["channel"].strip()
                    if channel_name:
                        config["windows_process_telemetry"]["channel"] = channel_name
                if "event_id" in wpt_cfg:
                    val = wpt_cfg["event_id"]
                    if isinstance(val, int) and not isinstance(val, bool) and val > 0:
                        config["windows_process_telemetry"]["event_id"] = int(val)
                if "max_events_per_query" in wpt_cfg:
                    val = wpt_cfg["max_events_per_query"]
                    if isinstance(val, int) and not isinstance(val, bool) and val > 0:
                        config["windows_process_telemetry"]["max_events_per_query"] = min(int(val), 1000)
                if "query_timeout_seconds" in wpt_cfg:
                    val = wpt_cfg["query_timeout_seconds"]
                    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
                        config["windows_process_telemetry"]["query_timeout_seconds"] = float(val)
                if "dedup_tolerance_seconds" in wpt_cfg:
                    val = wpt_cfg["dedup_tolerance_seconds"]
                    if isinstance(val, (int, float)) and not isinstance(val, bool) and val >= 0:
                        config["windows_process_telemetry"]["dedup_tolerance_seconds"] = float(val)
                if "require_command_line" in wpt_cfg:
                    config["windows_process_telemetry"]["require_command_line"] = bool(
                        wpt_cfg["require_command_line"]
                    )

            sysmon_cfg = ce_config.get("sysmon_telemetry", {})
            if isinstance(sysmon_cfg, dict):
                if "enabled" in sysmon_cfg:
                    config["sysmon_telemetry"]["enabled"] = bool(sysmon_cfg["enabled"])
                if "channel" in sysmon_cfg and isinstance(sysmon_cfg["channel"], str):
                    chan = sysmon_cfg["channel"].strip()
                    if chan:
                        config["sysmon_telemetry"]["channel"] = chan
                if "enable_process_events" in sysmon_cfg:
                    config["sysmon_telemetry"]["enable_process_events"] = bool(
                        sysmon_cfg["enable_process_events"]
                    )
                if "enable_network_events" in sysmon_cfg:
                    config["sysmon_telemetry"]["enable_network_events"] = bool(
                        sysmon_cfg["enable_network_events"]
                    )
                if "max_events_per_query" in sysmon_cfg:
                    val = sysmon_cfg["max_events_per_query"]
                    if isinstance(val, int) and not isinstance(val, bool) and val > 0:
                        config["sysmon_telemetry"]["max_events_per_query"] = min(int(val), 1000)
                if "query_timeout_seconds" in sysmon_cfg:
                    val = sysmon_cfg["query_timeout_seconds"]
                    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
                        config["sysmon_telemetry"]["query_timeout_seconds"] = float(val)
                if "dedup_tolerance_seconds" in sysmon_cfg:
                    val = sysmon_cfg["dedup_tolerance_seconds"]
                    if isinstance(val, (int, float)) and not isinstance(val, bool) and val >= 0:
                        config["sysmon_telemetry"]["dedup_tolerance_seconds"] = float(val)

            fw_cfg = ce_config.get("firewall_enforcement", {})
            if isinstance(fw_cfg, dict):
                if "enabled" in fw_cfg:
                    config["firewall_enforcement"]["enabled"] = bool(fw_cfg["enabled"])
                if "dry_run" in fw_cfg:
                    val = fw_cfg["dry_run"]
                    config["firewall_enforcement"]["dry_run"] = val if isinstance(val, bool) else True
                if "auto_block_suspicious" in fw_cfg:
                    config["firewall_enforcement"]["auto_block_suspicious"] = bool(
                        fw_cfg["auto_block_suspicious"]
                    )
                if "block_threshold" in fw_cfg:
                    val = fw_cfg["block_threshold"]
                    if isinstance(val, int) and not isinstance(val, bool) and val >= 0:
                        config["firewall_enforcement"]["block_threshold"] = int(val)
                if "blocked_severities" in fw_cfg and isinstance(fw_cfg["blocked_severities"], list):
                    config["firewall_enforcement"]["blocked_severities"] = [
                        str(s).upper() for s in fw_cfg["blocked_severities"] if isinstance(s, str)
                    ]
                if "blocked_indicators" in fw_cfg and isinstance(fw_cfg["blocked_indicators"], list):
                    config["firewall_enforcement"]["blocked_indicators"] = [
                        str(i) for i in fw_cfg["blocked_indicators"] if isinstance(i, str)
                    ]
                if "allowed_executables" in fw_cfg and isinstance(fw_cfg["allowed_executables"], list):
                    config["firewall_enforcement"]["allowed_executables"] = [
                        str(a) for a in fw_cfg["allowed_executables"] if isinstance(a, str)
                    ]
                if "rule_prefix" in fw_cfg and isinstance(fw_cfg["rule_prefix"], str):
                    rp = fw_cfg["rule_prefix"].strip()
                    if rp:
                        config["firewall_enforcement"]["rule_prefix"] = rp
                if "rule_group" in fw_cfg and isinstance(fw_cfg["rule_group"], str):
                    rg = fw_cfg["rule_group"].strip()
                    if rg:
                        config["firewall_enforcement"]["rule_group"] = rg
                if "timeout_seconds" in fw_cfg:
                    val = fw_cfg["timeout_seconds"]
                    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
                        config["firewall_enforcement"]["timeout_seconds"] = float(val)

    except Exception as e:
        logging.getLogger("endpoint_monitor").debug(
            f"Could not load controlled_execution config from {config_path}: {e}"
        )

    return config
