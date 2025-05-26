from django.db import models

class ScanLog(models.Model):
    file_path = models.CharField(max_length=1024)
    result = models.CharField(max_length=50)
    timestamp = models.DateTimeField()
    
    def __str__(self):
        return f"{self.file_path} - {self.result} at {self.timestamp}"
