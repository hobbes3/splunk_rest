# Optional variable for your convienence.
DEBUG = False

# Number of threads to create for multiprocessing.
THREADS = 8
# Sleep for a random seconds between SPLUNK_MIN and SLEEP_MAX (floating number) before a request call.
# Set both SLEEP_ to 0 to disable sleeping.
SPLUNK_MIN = 0.01
SLEEP_MAX = 0.1
# Set TEXT_TRUNCATE to 0 to log entire data on sending and receiving (not recommended).
TEXT_TRUNCATE = 300

# Log will be saved at $SPLUNK_HOME/var/log/splunk/ and can be searched via `index=internal`.
# Size of each log file.
# 1 MB = 1 * 1024 * 1024
LOG_ROTATION_BYTES = 25 * 1024 * 1024
# Maximum number of log files.
LOG_ROTATION_LIMIT = 5

# No trailing slash.
SPLUNK_HOME = "/opt/splunk"

# Splunk or Cribl HEC info.
HTTP_URL = "https://localhost:8088/services/collector/event"
HTTP_HEADERS = {
    "Authorization": "Splunk xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}

# Set REST API specific variable like API keys and Splunk index below.
