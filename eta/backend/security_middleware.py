"""
Enhanced Security Middleware
Rate limiting, logging, monitoring, and API authentication hardening.
"""
import os
import time
import logging
import ipaddress
from typing import Callable
from functools import wraps

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import Headers

logger = logging.getLogger(__name__)


# === Rate Limiter ===

class RateLimiter:
    """Enhanced rate limiter with per-endpoint limits."""

    def __init__(self):
        self.requests = {}  # {ip: [(timestamp, endpoint)]}
        self.cleanup_interval = 3600  # cleanup every hour
        self.last_cleanup = time.time()

    def check_rate_limit(
        self,
        ip: str,
        endpoint: str,
        limit: int = 100,
        window: int = 60
    ) -> bool:
        """Check if request is within rate limit."""
        now = time.time()

        # Cleanup old entries
        if now - self.last_cleanup > self.cleanup_interval:
            self.cleanup_old_entries()
            self.last_cleanup = now

        key = f"{ip}:{endpoint}"
        if key not in self.requests:
            self.requests[key] = []

        # Remove old entries outside window
        self.requests[key] = [
            t for t in self.requests[key]
            if now - t < window
        ]

        # Check limit
        if len(self.requests[key]) >= limit:
            return False

        # Add current request
        self.requests[key].append(now)
        return True

    def cleanup_old_entries(self):
        """Remove old rate limit entries."""
        now = time.time()
        for key in list(self.requests.keys()):
            self.requests[key] = [
                t for t in self.requests[key]
                if now - t < 3600
            ]
            if not self.requests[key]:
                del self.requests[key]


# Global rate limiter
rate_limiter = RateLimiter()


# === Per-Endpoint Rate Limits ===
ENDPOINT_LIMITS = {
    "/api/auth/login": (10, 60),       # 10 requests per minute
    "/api/auth/register": (5, 60),   # 5 per minute
    "/api/analyze-email": (50, 60),  # 50 per minute
    "/api/analyze-batch": (10, 60),   # 10 per minute
    "/api/extension-scan": (30, 60), # 30 per minute
    "/api/reports/report": (20, 60), # 20 per minute
}


def check_endpoint_limit(request: Request) -> bool:
    """Check rate limit for specific endpoint."""
    path = request.url.path

    # Get limit for endpoint
    for endpoint, (limit, window) in ENDPOINT_LIMITS.items():
        if path.startswith(endpoint):
            ip = get_client_ip(request)
            return rate_limiter.check_rate_limit(ip, endpoint, limit, window)

    # Default limit
    ip = get_client_ip(request)
    return rate_limiter.check_rate_limit(ip, "default", 100, 60)


# === Logging Middleware ===

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request/response logging."""

    async def dispatch(self, request: Request, call_next: Callable):
        start_time = time.time()

        # Get request info
        ip = get_client_ip(request)
        method = request.method
        path = request.url.path

        # Log request
        logger.info(f"Request: {method} {path} from {ip}")

        # Process request
        try:
            response = await call_next(request)

            # Calculate duration
            duration = time.time() - start_time

            # Log response
            logger.info(
                f"Response: {method} {path} "
                f"status={response.status_code} "
                f"duration={duration:.3f}s"
            )

            return response
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"Error: {method} {path} "
                f"error={str(e)} "
                f"duration={duration:.3f}s"
            )
            raise


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self'; "
            "font-src 'self' data:; "
            "frame-ancestors 'none';"
        )

        # Only send HSTS on HTTPS connections — sending it over HTTP locks browsers into HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


class IPBlocklistMiddleware(BaseHTTPMiddleware):
    """Block requests from specific IPs."""

    BLOCKED_IPS = set(os.environ.get("BLOCKED_IPS", "").split(","))

    async def dispatch(self, request: Request, call_next: Callable):
        ip = get_client_ip(request)

        if ip in self.BLOCKED_IPS:
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied"}
            )

        return await call_next(request)


# === Helpers ===

def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """Get real client IP, respecting proxy headers. Only trust IPs that parse as valid addresses."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        if _is_valid_ip(ip):
            return ip

    real_ip = request.headers.get("X-Real-IP", "").strip()
    if real_ip and _is_valid_ip(real_ip):
        return real_ip

    cf_ip = request.headers.get("CF-Connecting-IP", "").strip()
    if cf_ip and _is_valid_ip(cf_ip):
        return cf_ip

    return request.client.host if request.client else "unknown"


def require_api_key(request: Request) -> str:
    """Require API key for certain endpoints."""
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")
    return api_key


def log_api_call(endpoint: str, user_id: int = None, result: str = "success"):
    """Log API calls for monitoring."""
    logger.info(f"API: endpoint={endpoint} user_id={user_id} result={result}")


# === Decorator ===

def rate_limit(limit: int = 100, window: int = 60):
    """Decorator to apply rate limiting to endpoints."""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            ip = get_client_ip(request)
            if not rate_limiter.check_rate_limit(ip, request.url.path, limit, window):
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded"
                )
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator


# === Metrics ===

class RequestMetrics:
    """Track request metrics."""

    def __init__(self):
        self.total_requests = 0
        self.total_errors = 0
        self.endpoints = {}  # {endpoint: count}

    def record_request(self, endpoint: str, success: bool = True):
        """Record a request."""
        self.total_requests += 1
        if not success:
            self.total_errors += 1

        if endpoint not in self.endpoints:
            self.endpoints[endpoint] = 0
        self.endpoints[endpoint] += 1

    def get_stats(self) -> dict:
        """Get metrics."""
        return {
            "total_requests": self.total_requests,
            "total_errors": self.total_errors,
            "error_rate": self.total_errors / max(1, self.total_requests),
            "endpoints": self.endpoints,
        }


# Global metrics
metrics = RequestMetrics()


__all__ = [
    'RateLimiter',
    'rate_limiter',
    'ENDPOINT_LIMITS',
    'check_endpoint_limit',
    'RequestLoggingMiddleware',
    'SecurityHeadersMiddleware',
    'IPBlocklistMiddleware',
    'get_client_ip',
    'require_api_key',
    'log_api_call',
    'rate_limit',
    'metrics',
    'RequestMetrics',
]