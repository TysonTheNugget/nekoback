# Gunicorn configuration file
timeout = 60  # Increased worker timeout to handle long-running requests
workers = 2   # Conservative number of workers to prevent memory exhaustion
threads = 4   # Enable threading for better concurrency
worker_class = 'sync'  # Use sync workers for simplicity
loglevel = 'info'  # Set log level to info for debugging
accesslog = '-'  # Log to stdout
errorlog = '-'   # Log to stdout