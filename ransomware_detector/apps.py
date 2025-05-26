# apps.py
from django.apps import AppConfig
import threading

class RansomwareDetectorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ransomware_detector'

    def ready(self):
        if not hasattr(self, '_monitor_started'):
            def start_in_background():
                from core.ransomware_monitor import start_monitoring
                start_monitoring()

            threading.Thread(target=start_in_background, daemon=True).start()
            self._monitor_started = True
