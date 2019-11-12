#!/usr/bin/env python
# hobbes3

import requests
import os
import sys
import time
import json
import traceback
import inspect
import functools
import argparse
import logging
import logging.handlers
from argparse import ArgumentParser
from io import StringIO
from pythonjsonlogger import jsonlogger
from random import uniform
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3.util.retry import Retry
from tqdm import tqdm
from multiprocessing import Lock
from multiprocessing.dummy import Pool
from pathlib import Path
from secrets import token_urlsafe

from settings import *

def retry_session(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504]):
    s = RetrySession()
    s.verify = False
    retries = Retry(total=total, backoff_factor=backoff_factor, status_forcelist=status_forcelist, method_whitelist=frozenset(['GET', 'POST']))
    adapter = HTTPAdapter(max_retries=retries)
    s.mount('http://', adapter)
    s.mount('https://', adapter)

    return s

class RetrySession(requests.Session):
    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def request(self, method, url, headers=None, files=None, data=None, params=None, auth=None, cookies=None, hooks=None, json=None, timeout=None, **kwargs):
        t0 = time.time()

        # Not sure how to do this part
        #params = params if "params" in locals() else None
        #headers = headers if "headers" in locals() else None
        #auth = auth if "auth" in locals() else None
        #data = data if "data" in locals() else None
        #timeout = timeout if "timeout" in locals() else None

        kwargs.setdefault("params")
        kwargs.setdefault("headers")
        kwargs.setdefault("auth")
        kwargs.setdefault("data")
        kwargs.setdefault("timeout")

        meta = {
            "request_id": token_urlsafe(16)
        }

        sleep = uniform(SLEEP_START, SLEEP_END)

        log("Sleeping for {} seconds.".format(sleep), extra=meta)
        time.sleep(sleep)
        r = None

        try:
            meta_request = meta.copy()
            meta_request["request"] = {
                "method": method,
                "url": url,
            }
            if params:
                meta_request["request"]["params"] = params
            if headers:
                meta_request["request"]["headers"] = headers
            if auth:
                meta_request["request"]["auth"] = auth
            if data:
                meta_request["request"]["data"] = data if len(data) <= TEXT_TRUNCATE else data[:TEXT_TRUNCATE]+" (truncated)..."
            if timeout:
                meta_request["request"]["timeout"] = timeout

            log("Trying new request...".format(method, url), extra=meta_request)
            if data:
                log("Sending {} bytes of data".format(len(data)), level="debug", extra=meta)

            r = super().request(method, url, **kwargs)
        except Exception:
            traceback.print_exc()
            log("An exception occured!", level="exception", extra=meta)
        else:
            meta_response = meta.copy()
            meta_response["response"] = {
                "status_code": r.status_code,
                "reason": r.reason,
                "headers": dict(r.headers),
            }

            if r.text:
                meta_response["response"]["text"] = r.text if len(r.text) <= TEXT_TRUNCATE else r.text[:TEXT_TRUNCATE]+" (truncated)..."

            if r.status_code == 200:
                log("Eventually worked.", extra=meta_response)
            else:
                log("Eventually worked but with status code {}!".format(r.status_code), level="warning", extra=meta_response)

            if r.text:
                log("Got {} bytes of data.".format(len(r.text)), level="debug", extra=meta)
            else:
                log("Empty response!", level="warning", extra=meta)
        finally:
            log("Took {} seconds.".format(time.time() - t0), extra=meta)
            return r

def log(msg, level="info", extra=None, stdout=False):
    if extra is None:
        extra = {}

    extra["session_id"] = sid

    if level == "debug":
        logger.debug(msg, extra=extra)
    elif level == "warning":
        logger.warning(msg, extra=extra)
    elif level == "exception":
        logger.exception(msg, extra=extra)
    else:
        logger.info(msg, extra=extra)

    if stdout:
        print(msg, extra)

def rest_wrapped(func):
    def gracefully_exit():
        with lock:
            log("INCOMPLETE.", level="warning", extra={"elapsed_sec": time.time() - start_time}, stdout=True)
            os._exit(1)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        log("START.", stdout=True)

        if not Path(bin_path / "settings.py").exists():
            log("The config file, settings.py, doesn't exist! Please copy, edit, and rename default_settings.py to settings.py.", level="warning", stdout=True)
            os._exit(1)

        if DEBUG:
            log("DEBUG on!", level="warning", stdout=True)

        print("Log file at {}.".format(log_file))

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        try:
            print("Press ctrl-c to cancel at any time.")

            func(*args, **kwargs)

            pool.close()
            pool.join()
        except KeyboardInterrupt:
            log("Caught KeyboardInterrupt! Cleaning up and terminating workers. Please wait...", level="warning", stdout=True)
            pool.terminate()
            pool.join()
            gracefully_exit()
        except Exception:
            traceback.print_exc()
            log("An exception occured!", level="exception")
            pool.terminate()
            pool.join()
            gracefully_exit()

        log("DONE.", extra={"elapsed_sec": time.time() - start_time}, stdout=True)

    return wrapper

# I know it's not best practice not to run code import time,
# but I'm not sure how else to do this part.
# Especially defining the some path strings and the logger.
start_time = time.time()

filename = inspect.stack()[-1][1]
script_file = Path(filename).resolve()
script_filename = script_file.stem
bin_path = script_file.parents[0]
# Save logs the Splunk directory to be picked up by `index=_internal`.
log_file = Path(os.environ["SPLUNK_HOME"] + "/var/log/splunk/" + script_filename + ".log")

sid = token_urlsafe(8)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=LOG_ROTATION_BYTES, backupCount=LOG_ROTATION_LIMIT)
handler.setFormatter(jsonlogger.JsonFormatter("(asctime) (levelname) (threadName) (message)"))
logger.addHandler(handler)

parser = ArgumentParser()
parser.add_argument("-s", "--silent", help="suppresses stdout (for Splunk scripted inputs)", action="store_true")
args = parser.parse_args()

if args.silent:
    sys.stdout = StringIO()

lock = Lock()
pool = Pool(THREADS)
