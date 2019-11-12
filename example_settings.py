# Number of threads to create for multiprocessing.
THREADS = 8
# Sleep for a random seconds between SLEEP_START and SLEEP_END (floating number) before a request call.
# Set both SLEEP_ to 0 to disable sleeping.
SLEEP_START = 0.01
SLEEP_END = 0.1
# Set TEXT_TRUNCATE to 0 to log entire data on sending and receiving (not recommended).
TEXT_TRUNCATE = 300

# Size of each log file.
# 1 MB = 1 * 1024 * 1024
LOG_ROTATION_BYTES = 25 * 1024 * 1024
# Maximum number of log files.
LOG_ROTATION_LIMIT = 5

# Splunk or Cribl HEC info
HTTP_URL = "https://localhost:8088/services/collector/event"
HTTP_HEADERS = {
    "Authorization": "Splunk xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}

# Optional variable for your convienence.
DEBUG = False
