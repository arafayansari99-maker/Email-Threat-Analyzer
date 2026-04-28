"""
Health Monitoring Service - Background health checks and alerts.
"""
import asyncio
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from typing import Callable, Optional

import requests

logger = logging.getLogger(__name__)

# Health check configuration
HEALTH_CHECK_INTERVAL = int(os.environ.get("HEALTH_CHECK_INTERVAL", "60"))  # seconds
HEALTH_CHECK_TIMEOUT = int(os.environ.get("HEALTH_CHECK_TIMEOUT", "10"))  # seconds
HEALTH_CHECK_URL = os.environ.get("HEALTH_CHECK_URL", "http://127.0.0.1:8001/api/admin/health")
HEALTH_CHECK_RETRIES = int(os.environ.get("HEALTH_CHECK_RETRIES", "3"))
HEALTH_CHECK_RETRY_DELAY = int(os.environ.get("HEALTH_CHECK_RETRY_DELAY", "5"))  # seconds


class HealthMonitor:
    """Background health monitoring service."""

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: list[Callable] = []
        self._last_check: Optional[datetime] = None
        self._last_status: Optional[bool] = None
        self._consecutive_failures = 0
        self._failure_threshold = 3
        self._last_notification: Optional[datetime] = None
        self._notification_cooldown = 300  # 5 minutes between notifications

    def start(self):
        """Start the health monitoring service."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="HealthMonitor")
        self._thread.start()
        logger.info("Health monitoring service started")

    def stop(self):
        """Stop the health monitoring service."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Health monitoring service stopped")

    def register_callback(self, callback: Callable):
        """Register a callback to be called on status changes."""
        self._callbacks.append(callback)

    def get_status(self) -> dict:
        """Get current health status."""
        return {
            "running": self._running,
            "last_check": self._last_check.isoformat() if self._last_check else None,
            "last_status": self._last_status,
            "consecutive_failures": self._consecutive_failures,
        }

    def _run_loop(self):
        """Main health check loop."""
        while self._running:
            try:
                self._perform_check()
            except Exception as e:
                logger.error(f"Health check error: {e}")
            time.sleep(HEALTH_CHECK_INTERVAL)

    def _perform_check(self):
        """Perform a health check."""
        now = datetime.utcnow()
        status = False
        error_msg = None

        for attempt in range(HEALTH_CHECK_RETRIES):
            try:
                response = requests.get(
                    HEALTH_CHECK_URL,
                    timeout=HEALTH_CHECK_TIMEOUT
                )
                if response.status_code == 200:
                    status = True
                    break
                error_msg = f"Status code: {response.status_code}"
            except requests.exceptions.RequestException as e:
                error_msg = str(e)
                if attempt < HEALTH_CHECK_RETRIES - 1:
                    time.sleep(HEALTH_CHECK_RETRY_DELAY)

        self._last_check = now

        # Check for status change
        if status != self._last_status:
            logger.info(f"Health status changed: {self._last_status} -> {status}")
            self._notify_callbacks(status, error_msg)

        # Track consecutive failures
        if status:
            self._consecutive_failures = 0
        else:
            self._consecutive_failures += 1
            logger.warning(f"Health check failed ({self._consecutive_failures}x): {error_msg}")

            # Check if we should trigger auto-restart
            if self._consecutive_failures >= self._failure_threshold:
                self._trigger_auto_restart()

        self._last_status = status

    def _notify_callbacks(self, healthy: bool, error: Optional[str] = None):
        """Notify registered callbacks of status change."""
        # Check cooldown to avoid notification spam
        if self._last_notification:
            time_since_notification = (datetime.utcnow() - self._last_notification).total_seconds()
            if time_since_notification < self._notification_cooldown:
                return

        for callback in self._callbacks:
            try:
                callback(healthy, error)
            except Exception as e:
                logger.error(f"Callback error: {e}")

        self._last_notification = datetime.utcnow()

    def _trigger_auto_restart(self):
        """Attempt to auto-restart the service."""
        logger.warning("Health check threshold reached - attempting auto-restart...")

        # Try to restart the backend process
        restart_script = os.environ.get("HEALTH_RESTART_SCRIPT", "")
        if restart_script and os.path.exists(restart_script):
            try:
                import subprocess
                subprocess.Popen(restart_script, shell=True)
                logger.info("Auto-restart initiated")
                # Reset failures after restart attempt
                self._consecutive_failures = 0
            except Exception as e:
                logger.error(f"Auto-restart failed: {e}")
        else:
            logger.warning("No restart script configured")

    def check_now(self) -> bool:
        """Perform an immediate health check."""
        status = False
        try:
            response = requests.get(HEALTH_CHECK_URL, timeout=HEALTH_CHECK_TIMEOUT)
            status = response.status_code == 200
        except requests.exceptions.RequestException:
            pass
        return status


class AlertService:
    """Service for sending alerts via email or in-app notifications."""

    def __init__(self):
        self._listeners: list[Callable] = []

    def add_listener(self, callback: Callable):
        """Add a listener for alerts."""
        self._listeners.append(callback)

    def send_alert(
        self,
        alert_type: str,
        title: str,
        message: str,
        severity: str = "warning",
    ):
        """Send an alert to all listeners."""
        alert = {
            "type": alert_type,
            "title": title,
            "message": message,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
        }

        logger.info(f"[ALERT] {severity.upper()}: {title} - {message}")

        for listener in self._listeners:
            try:
                listener(alert)
            except Exception as e:
                logger.error(f"Alert listener error: {e}")

    def send_health_alert(self, healthy: bool, error: Optional[str] = None):
        """Send health status alert."""
        if healthy:
            self.send_alert(
                "health_ok",
                "API Recovered",
                "ETA API is back online and healthy.",
                "success",
            )
        else:
            self.send_alert(
                "health_down",
                "API Down",
                f"ETA API is not responding. Error: {error}",
                "critical",
            )

    def send_threat_alert(
        self,
        scan_id: str,
        verdict: str,
        risk_score: int,
        sender: str,
    ):
        """Send high-risk threat alert."""
        self.send_alert(
            "high_threat",
            f"High-Risk Threat Detected",
            f"Scan {scan_id}: {verdict} (risk: {risk_score}) from {sender}",
            "warning" if verdict == "suspicious" else "critical",
        )

    def send_digest(self, stats: dict):
        """Send periodic digest."""
        self.send_alert(
            "daily_digest",
            "Daily Security Digest",
            f"Scans: {stats.get('total', 0)}, Threats: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}",
            "info",
        )


# Singleton instances
health_monitor = HealthMonitor()
alert_service = AlertService()