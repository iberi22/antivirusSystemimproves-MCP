from __future__ import annotations

from typing import Any, Optional
import os
import json

import httpx

from . import db
from . import config as cfg


DEFAULT_WEBHOOK_ENV = "ALERT_WEBHOOK_URL"


def notify_log(level: str, message: str, *, code: Optional[str] = None) -> dict:
    try:
        db.log_event(level, message, code=code)
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def notify_webhook(url: str, event: str, level: str, data: Optional[dict] = None, *, timeout: float = cfg.WEBHOOK_TIMEOUT) -> dict:
    payload = {
        "event": event,
        "level": level,
        "data": data or {},
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json=payload)
            return {"ok": resp.status_code // 100 == 2, "status": resp.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def notify_webhook_if_configured(event: str, level: str, data: Optional[dict] = None, *, env_var: str = DEFAULT_WEBHOOK_ENV) -> None:
    if not cfg.ENABLE_ALERTS:
        return
    url = os.getenv(env_var, "").strip()
    if not url:
        return
    try:
        notify_webhook(url, event, level, data)
    except Exception:
        pass


def notify_toast(title: str, message: str) -> dict:
    # Best-effort toast; requires optional win10toast or winrt packages.
    try:
        from win10toast import ToastNotifier  # type: ignore

        toaster = ToastNotifier()
        toaster.show_toast(title, message, duration=5, threaded=True)
        return {"ok": True, "method": "win10toast"}
    except Exception:
        pass
    # Attempt winrt approach
    try:
        # Lazy import to avoid dependency issues when not present
        import winrt.windows.ui.notifications as notifications  # type: ignore
        import winrt.windows.data.xml.dom as dom  # type: ignore

        t = f"""
        <toast>
            <visual>
                <binding template="ToastGeneric">
                    <text>{title}</text>
                    <text>{message}</text>
                </binding>
            </visual>
        </toast>
        """
        xml = dom.XmlDocument()
        xml.load_xml(t)
        notifier = notifications.ToastNotificationManager.create_toast_notifier("MCP Windows Admin")
        notification = notifications.ToastNotification(xml)
        notifier.show(notification)
        return {"ok": True, "method": "winrt"}
    except Exception:
        pass
    return {"ok": False, "error": "no_toast_backend"}
