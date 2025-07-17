import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'your_project_name.settings')

app = Celery('your_project_name')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

app.conf.beat_schedule = {
    'detect-anomalies-every-hour': {
        'task': 'ip_tracking.tasks.detect_anomalies',
        'schedule': 3600.0,  # seconds = 1 hour
    },
}
