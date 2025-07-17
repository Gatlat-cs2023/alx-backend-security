from .models import RequestLog
from datetime import datetime

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
