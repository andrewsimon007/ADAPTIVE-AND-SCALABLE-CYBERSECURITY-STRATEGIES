# core/management/commands/monitor_files.py

from django.core.management.base import BaseCommand
from core.ransomware_monitor import start_monitoring

class Command(BaseCommand):
    help = 'Start ransomware detection and monitoring manually'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("🔐 Starting ransomware monitor..."))
        start_monitoring()
