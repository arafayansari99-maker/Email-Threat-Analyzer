"""
Webhook Notification Service - Sends notifications to Slack, Teams, Discord, etc.
"""
import os
import json
import logging
from typing import Optional
from datetime import datetime
import requests

logger = logging.getLogger(__name__)

# Webhook configuration
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK", "")
TEAMS_WEBHOOK = os.environ.get("TEAMS_WEBHOOK", "")
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK", "")


class WebhookService:
    """Webhook notification service for Slack, Teams, Discord."""

    def __init__(self):
        self.enabled = bool(SLACK_WEBHOOK or TEAMS_WEBHOOK or DISCORD_WEBHOOK)

    def _send_slack(self, message: str, color: str, fields: list = None) -> bool:
        """Send to Slack."""
        if not SLACK_WEBHOOK:
            return False

        payload = {
            "attachments": [{
                "color": color,
                "fields": fields or [],
                "text": message,
                "footer": "ETA Security",
                "ts": int(datetime.utcnow().timestamp()),
            }]
        }

        try:
            response = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Slack webhook failed: {e}")
            return False

    def _send_teams(self, message: str, color: str) -> bool:
        """Send to Microsoft Teams."""
        if not TEAMS_WEBHOOK:
            return False

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color.replace("#", ""),
            "summary": "ETA Security Alert",
            "sections": [{
                "activityTitle": "ETA Security Alert",
                "activitySubtitle": message,
                "markdown": True,
            }],
        }

        try:
            response = requests.post(TEAMS_WEBHOOK, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Teams webhook failed: {e}")
            return False

    def _send_discord(self, message: str, color: int) -> bool:
        """Send to Discord."""
        if not DISCORD_WEBHOOK:
            return False

        payload = {
            "embeds": [{
                "title": "ETA Security Alert",
                "description": message,
                "color": color,
                "footer": {"text": "ETA Security"},
                "timestamp": datetime.utcnow().isoformat(),
            }]
        }

        try:
            response = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Discord webhook failed: {e}")
            return False

    def send_alert(self, title: str, message: str, severity: str = "info") -> bool:
        """Send an alert to all configured webhooks."""
        # Color mappings
        colors = {
            "info": {"slack": "#06B6D4", "teams": "#06B6D4", "discord": 0x06B6D4},
            "warning": {"slack": "#F59E0B", "teams": "#F59E0B", "discord": 0xF59E0B},
            "error": {"slack": "#EF4444", "teams": "#EF4444", "discord": 0xEF4444},
            "success": {"slack": "#10B981", "teams": "#10B981", "discord": 0x10B981},
        }.get(severity, {"slack": "#06B6D4", "teams": "#06B6D4", "discord": 0x06B6D4})

        full_message = f"**{title}**\n{message}"

        results = []
        if SLACK_WEBHOOK:
            results.append(self._send_slack(full_message, colors["slack"]))
        if TEAMS_WEBHOOK:
            results.append(self._send_teams(full_message, colors["teams"]))
        if DISCORD_WEBHOOK:
            results.append(self._send_discord(full_message, colors["discord"]))

        return any(results) if results else True

    def notify_new_user(self, username: str, email: str) -> bool:
        """Notify admin of new user registration."""
        return self.send_alert(
            "New User Registration",
            f"User `{username}` ({email}) has registered and is pending approval.",
            "info"
        )

    def notify_user_approved(self, username: str) -> bool:
        """Notify admin when user is approved."""
        return self.send_alert(
            "User Approved",
            f"User `{username}` has been approved and can now login.",
            "success"
        )

    def notify_failed_login(self, email: str, ip: str, attempts: int) -> bool:
        """Notify of failed login attempts."""
        return self.send_alert(
            "Failed Login Attempts",
            f"Detected {attempts} failed login attempts for `{email}` from IP `{ip}`.",
            "warning"
        )

    def notify_threat_detected(self, filename: str, verdict: str, risk_score: float) -> bool:
        """Notify of detected threat."""
        color = "error" if verdict == "malicious" else "warning"
        return self.send_alert(
            f"Threat Detected: {verdict}",
            f"File: `{filename}`\nRisk Score: {risk_score}/100",
            color
        )


# Singleton instance
webhook_service = WebhookService()