from .models import RequestLog
from datetime import datetime
from django.http import HttpResponseForbidden
from .models import BlockedIP

import requests
from django.utils.timezone import now
from django.core.cache import cache
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP


class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Extract IP address
        ip_address = self.get_client_ip(request)
        path = request.path
        timestamp = datetime.now()

        # Save to database
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=timestamp,
            path=path
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """Get client IP address from request headers."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')

class IPBlockerMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP is blocked.")

        return self.get_response(request)

    def get_client_ip(self, request):
        # Try to get the real IP address even behind a proxy
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # Blocked IP logic
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP is blocked.")

        # Check cache
        location = cache.get(ip)
        if not location:
            try:
                res = requests.get(f"https://ipapi.co/{ip}/json/")
                data = res.json()
                location = {
                    "country": data.get("country_name", "Unknown"),
                    "city": data.get("city", "Unknown")
                }
            except Exception:
                location = {"country": "Unknown", "city": "Unknown"}

            cache.set(ip, location, timeout=60 * 60 * 24)  # 24 hours

        # Log
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            timestamp=now(),
            country=location["country"],
            city=location["city"]
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')
