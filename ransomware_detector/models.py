from django.db import models

class ScanLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    filename = models.CharField(max_length=255)
    action_taken = models.CharField(max_length=50)  # e.g., "Moved to Quarantine"
    
    def __str__(self):
        return f"{self.timestamp} - {self.filename} - {self.action_taken}"
