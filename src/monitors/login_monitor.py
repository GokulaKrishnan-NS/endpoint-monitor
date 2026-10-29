"""
User Logon and Session Monitor Module.

Observes active interactive and remote user logon sessions using psutil
and Windows security telemetry. Normalizes sessions into standardized Event objects.
"""

from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional
import uuid

import psutil

from src.models.event import Event


logger = logging.getLogger("endpoint_monitor")


class LoginMonitor:
    """
    Monitors active user sessions and flags abnormal logon patterns
    (e.g. unexpected service accounts in interactive sessions or multi-host access).
    """

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger or logging.getLogger("endpoint_monitor")
        self._known_users: Dict[str, float] = {}
        self._active_sessions: Dict[tuple, Dict[str, Any]] = {}

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """
        Query system for currently logged-in users via psutil.
        Handles permission errors and missing attributes gracefully.
        """
        sessions: List[Dict[str, Any]] = []
        try:
            users = psutil.users()
            for u in users:
                started_ts = getattr(u, "started", time.time())
                session_dict = {
                    "username": getattr(u, "name", "unknown"),
                    "terminal": getattr(u, "terminal", "console") or "console",
                    "host": getattr(u, "host", "localhost") or "localhost",
                    "started": started_ts,
                    "pid": getattr(u, "pid", None),
                }
                sessions.append(session_dict)
        except Exception as e:
            self.logger.debug(f"Failed to query active user sessions: {e}")

        return sessions

    def check_logon_events(self, new_only: bool = False) -> List[Event]:
        """
        Inspect current user sessions and generate standardized Event objects
        for user sessions. If new_only is True, only newly observed sessions
        and session termination events are emitted.
        """
        events: List[Event] = []
        sessions = self.get_active_sessions()
        current_sessions: Dict[tuple, Dict[str, Any]] = {}

        for s in sessions:
            user = s["username"]
            identity = (
                user.casefold(),
                s["terminal"],
                s["host"],
                s["started"],
                s.get("pid"),
            )
            current_sessions[identity] = s
            is_new_session = identity not in self._active_sessions
            is_new_user = user not in self._known_users
            self._known_users[user] = s["started"]
            if new_only and not is_new_session:
                continue

            # Evaluate risk
            indicators: List[str] = []
            risk_score = 0
            risk_level = "LOW"
            severity = "LOW"
            reasons: List[str] = []

            # Flag remote terminal connections
            if s["host"] not in ("localhost", "127.0.0.1", ""):
                indicators.append("remote_session_detected")
                risk_score += 2
                reasons.append(f"Remote logon session from host '{s['host']}'")

            # Flag potential service account interactive logons
            lower_user = user.lower()
            if any(svc in lower_user for svc in ["svc_", "service", "daemon", "sql"]):
                indicators.append("service_account_interactive_logon")
                risk_score += 3
                severity = "MEDIUM"
                risk_level = "MEDIUM"
                reasons.append(f"Potential service account logged into interactive session: '{user}'")

            stable_id = uuid.uuid5(uuid.NAMESPACE_OID, repr(identity))
            evt = Event(
                event_id=str(stable_id),
                timestamp=s["started"],
                event_type="user_logon",
                source="login_monitor",
                severity=severity,
                pid=s.get("pid"),
                username=user,
                indicators=indicators,
                risk_score=risk_score,
                risk_level=risk_level,
                risk_reasons=reasons if reasons else ["Standard user logon session"],
                metadata={
                    "terminal": s["terminal"],
                    "host": s["host"],
                    "is_new_user": is_new_user,
                    "is_new_session": is_new_session,
                },
            )
            events.append(evt)

        for identity, old_session in self._active_sessions.items():
            if identity in current_sessions:
                continue
            events.append(
                Event(
                    event_id=str(uuid.uuid5(uuid.NAMESPACE_OID, f"ended:{identity!r}")),
                    event_type="user_session_ended",
                    source="login_monitor",
                    severity="LOW",
                    pid=old_session.get("pid"),
                    username=old_session["username"],
                    risk_reasons=["Previously observed user session is no longer active"],
                    metadata={
                        "terminal": old_session["terminal"],
                        "host": old_session["host"],
                        "started": old_session["started"],
                    },
                )
            )

        self._active_sessions = current_sessions
        return events
