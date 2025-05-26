import os
import time
import hashlib
import logging
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from django.core.management.base import BaseCommand
from django.conf import settings
from core.models import ScanLog
from decouple import config
from twilio.rest import Client
import yara
import shutil


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

TWILIO_ACCOUNT_SID = config('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = config('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = config('TWILIO_PHONE_NUMBER')
USER_PHONE_NUMBER = config('USER_PHONE_NUMBER')


RULES_PATH = config('YARA_RULE_PATH')
rules = yara.compile(filepath=RULES_PATH)


WATCH_DIRECTORY = config('WATCH_DIRECTORY')
QUARANTINE_DIR = config('QUARANTINE_DIR')
BACKUP_DIR = config('BACKUP_DIR')
os.makedirs(BACKUP_DIR, exist_ok=True)
DECOY_FILES = [
    os.path.join(WATCH_DIRECTORY, 'project.xlsx'),
    os.path.join(WATCH_DIRECTORY, 'report.docx'),
    os.path.join(WATCH_DIRECTORY, 'presentation.pptx')
]

HASHES_FILE = os.path.join(WATCH_DIRECTORY, 'hashes.json')


os.makedirs(QUARANTINE_DIR, exist_ok=True)


client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
def send_alert(file_path):
    max_retries = 3
    for attempt in range(max_retries):
        try:
            message = client.messages.create(
                body=f"Ransomware detected and file quarantined: {file_path}",
                from_=TWILIO_PHONE_NUMBER,
                to=USER_PHONE_NUMBER
            )
            logging.info(f"Alert sent: {message.sid}")
            return
        except Exception as e:
            logging.error(f"Failed to send alert (attempt {attempt + 1}): {e}")
            time.sleep(2 ** attempt)


def get_file_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.warning(f"Could not hash file {file_path}: {e}")
        return None


def load_hashes():
    try:
        with open(HASHES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.warning(f"Could not load hashes: {e}")
        return {}



def save_hashes(hashes):
    with open(HASHES_FILE, 'w') as f:
        json.dump(hashes, f)

def backup_file(file_path):
     try:
        if not os.path.exists(file_path):
            return
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = os.path.basename(file_path)
        backup_name = f"{timestamp}_{filename}"
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        with open(file_path, 'rb') as src, open(backup_path, 'wb') as dst:
            dst.write(src.read())
        logging.info(f"Versioned backup created: {backup_name}")
     except Exception as e:
        logging.error(f"Failed to backup file {file_path}: {e}")

class RansomwareHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.hashes = load_hashes()

    def quarantine_file(self, file_path):
     try:
         filename = os.path.basename(file_path)
         timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
         quarantine_path = os.path.join(QUARANTINE_DIR, f"{timestamp}_{filename}")
         os.rename(file_path, quarantine_path)  
         logging.info(f"File quarantined: {quarantine_path}")
         send_alert(file_path)
        
        
         ScanLog.objects.create(
            file_path=file_path,
            result='Quarantined',
            timestamp=datetime.now()  
        )
     except Exception as e:
        logging.error(f"Failed to quarantine file {file_path}: {e}")

            
            
            

    def scan_file(self, file_path):
        if not os.path.exists(file_path):
            return

        if not file_path.endswith(('.docx', '.xlsx', '.pptx')):
                return
        try:
            matches = rules.match(filepath=file_path)
            if matches:
                logging.warning(f"Malicious pattern detected: {file_path}")
                self.quarantine_file(file_path)
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")

    def check_decoy(self):
     for decoy in DECOY_FILES:
        if not os.path.exists(decoy):
            logging.warning(f"Decoy file missing: {decoy}")
            send_alert(decoy)
            continue

        new_hash = get_file_hash(decoy)
        old_hash = self.hashes.get(decoy)

        if old_hash is None:
            
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            ext = os.path.splitext(decoy)[1]
            name = os.path.splitext(os.path.basename(decoy))[0]
            backup_name = f"{timestamp}_{name}{ext}"
            shutil.copy2(decoy, os.path.join(BACKUP_DIR, backup_name))
            logging.info(f"Versioned backup created: {backup_name}")
        elif old_hash != new_hash:
            logging.warning(f"Decoy tampering detected: {decoy}")
            self.quarantine_file(decoy)

        
        self.hashes[decoy] = new_hash
     save_hashes(self.hashes)

    def on_modified(self, event):
     if event.is_directory:
        return

     file_path = event.src_path

    
     if os.path.abspath(file_path) == os.path.abspath(HASHES_FILE):
        return

    
     if os.path.commonpath([file_path, BACKUP_DIR]) == os.path.abspath(BACKUP_DIR):
        return

    
     if not file_path.endswith(('.docx', '.xlsx', '.pptx')):
        return

     self.scan_file(file_path)
     backup_file(file_path)
     logging.info(f"File modified: {file_path}")


    def on_moved(self, event):
     if event.src_path in DECOY_FILES:
        logging.warning(f"Decoy file renamed or moved: {event.src_path} -> {event.dest_path}")
        send_alert(event.src_path)
        self.quarantine_file(event.dest_path)

              
            
    

def check_files(file_path):
    """
    Function to check whether a file is suspicious (likely ransomware-related).
    For now, it checks if the file has an uncommon extension or a specific pattern.
    """
    suspicious_extensions = [".exe", ".scr", ".bat", ".vbs", ".dll"]
    suspicious_keywords = ["ransom", "crypt", "encrypt"]

    
    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension in suspicious_extensions:
        return True

    
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
            for keyword in suspicious_keywords:
                if keyword.lower() in content.lower():
                    return True
    except Exception as e:
        
        print(f"Error reading file {file_path}: {e}")

    return False


    
def initialize_decoys_and_hashes():
    initial_hashes = {}
    decoy_content = {
        '.xlsx': b'\x50\x4B\x03\x04ExcelData',  
        '.docx': b'\x50\x4B\x03\x04WordData',
        '.pptx': b'\x50\x4B\x03\x04PowerPointData'
    }
   


    for decoy in DECOY_FILES:
        if not os.path.exists(decoy):
            ext = os.path.splitext(decoy)[1]
            content = decoy_content.get(ext, b'DummyData')
            with open(decoy, 'wb') as f:
                f.write(content)
            logging.info(f"Created decoy file: {decoy}")
        file_hash = get_file_hash(decoy)
        if file_hash:
            initial_hashes[decoy] = file_hash
        backup_file(decoy)
    save_hashes(initial_hashes)
    logging.info("Decoy files and initial hashes initialized.")
    
   

class Command(BaseCommand):
    help = 'Run ransomware detection service'

    def handle(self, *args, **options):
        
        initialize_decoys_and_hashes()

        event_handler = RansomwareHandler()
        observer = Observer()
        observer.schedule(event_handler, path=WATCH_DIRECTORY, recursive=True)
        observer.start()
        logging.info("Ransomware detection service started.")

        try:
            while True:
                event_handler.check_decoy()
                time.sleep(5)
        except KeyboardInterrupt:
            observer.stop()
            logging.info("Ransomware detection service stopped by user.")
        observer.join()



if __name__ == "__main__":
    print("This module is meant to be used via Django custom command.")
