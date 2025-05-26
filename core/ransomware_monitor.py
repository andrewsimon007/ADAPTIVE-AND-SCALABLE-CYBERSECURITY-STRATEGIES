import time
import logging
from watchdog.observers import Observer
from core.ransomware_engine import RansomwareHandler, initialize_decoys_and_hashes
from decouple import config

WATCH_DIRECTORY = config('WATCH_DIRECTORY')

def start_monitoring():
    logging.info("🔐 Initializing decoys and file hashes...")
    initialize_decoys_and_hashes()

    event_handler = RansomwareHandler()

    
    event_handler.check_decoy()

    observer = Observer()
    observer.schedule(event_handler, path=WATCH_DIRECTORY, recursive=True)
    observer.start()

    logging.info("Started monitoring for ransomware activity...")

    try:
        while True:
            time.sleep(10)  
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Monitoring stopped by user.")
    observer.join()
