from celery import shared_task
from django.utils.timezone import now, timedelta
from django.db.models import Count, Q
from .models import RequestLog, SuspiciousIP

@shared_task
def detect_anomalies():
    one_hour_ago = now() - timedelta(hours=1)

    # 1. Find IPs with more than 100 requests in last hour
    ip_request_counts = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=100)
    )

    # 2. Find IPs accessing sensitive paths in last hour
    sensitive_paths = ['/admin', '/login']
    suspicious_path_ips = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago, path__in=sensitive_paths)
        .values_list('ip_address', flat=True)
        .distinct()
    )

    # Flag IPs with high request count
    for ip_data in ip_request_counts:
        ip = ip_data['ip_address']
        count = ip_data['request_count']
        reason = f"High request volume: {count} requests in last hour"
        SuspiciousIP.objects.get_or_create(ip_address=ip, defaults={'reason': reason})

    # Flag IPs accessing sensitive paths
    for ip in suspicious_path_ips:
        reason = "Accessed sensitive path (/admin or /login)"
        SuspiciousIP.objects.get_or_create(ip_address=ip, defaults={'reason': reason})
