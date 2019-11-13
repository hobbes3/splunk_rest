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

    def request(self, method, url, **kwargs):
        t0 = time.time()

        rid = {
            "request_id": token_urlsafe(16)
        }

        sleep = uniform(SPLUNK_MIN, SLEEP_MAX)

        meta_sleep = rid.copy()
        meta_sleep["sleep_sec"] = sleep
        log("Sleeping.", extra=meta_sleep, stdout=False)
        time.sleep(sleep)
        r = None

        try:
            meta_request = rid.copy()
            meta_request["request"] = {
                "method": method,
                "url": url,
            }

            for k, v in kwargs.items():
                if k == "data":
                    data_size = len(v)
                    meta_request["request"]["data_size"] = data_size
                    if data_size <= TEXT_TRUNCATE:
                        meta_request["request"]["data"] = v
                        meta_request["request"]["data_truncated"] = False
                    else:
                        meta_request["request"]["data"] = v[:TEXT_TRUNCATE]+" ..."
                        meta_request["request"]["data_truncated"] = True
                else:
                    meta_request["request"][k] = v

            log("Request start.", extra=meta_request, stdout=False)

            r = super().request(method, url, **kwargs)
        except Exception:
            traceback.print_exc()
            log("An exception occured!", level="exception", extra=rid, stdout=False)
        else:
            meta_response = rid.copy()
            meta_response["response"] = {
                "ok": r.ok,
                "encoding": r.encoding,
                "apparent_encoding": r.apparent_encoding,
                "status_code": r.status_code,
                "reason": r.reason,
                "headers": dict(r.headers),
                "links": r.links,
                "elapsed": r.elapsed,
                "is_redirect": r.is_redirect,
                "is_permanent_redirect": r.is_permanent_redirect,
                "url": r.url,
            }

            if r.text:
                data_size = len(r.text)
                meta_response["response"]["data_size"] = data_size
                if data_size <= TEXT_TRUNCATE:
                    meta_response["response"]["data"] = r.text
                    meta_response["response"]["data_truncated"] = False
                else:
                    meta_response["response"]["data"] = r.text[:TEXT_TRUNCATE]+" ..."
                    meta_response["response"]["data_truncated"] = True
            else:
                log("Empty response received!", level="warning", extra=rid, stdout=False)

            if r.status_code == 200:
                log("Response received.", extra=meta_response, stdout=False)
            else:
                log("Response received but with non-OK status code!", level="warning", extra=meta_response, stdout=False)

        finally:
            m = rid.copy()
            m["request_elapsed_sec"] = time.time() - t0
            log("Request end.", extra=m, stdout=False)
            return r

def log(msg, level="info", extra=None, stdout=True):
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
        print(level.upper(), msg, extra)

def rest_wrapped(func):
    def gracefully_exit():
        with lock:
            log("SCRIPT INCOMPLETE.", level="warning", extra={"script_elapsed_sec": time.time() - start_time})
            os._exit(1)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        log("SCRIPT START.")

        if not Path(bin_path / "settings.py").exists():
            log("The config file, settings.py, doesn't exist! Please copy, edit, and rename default_settings.py to settings.py.", level="warning")
            os._exit(1)

        if DEBUG:
            log("DEBUG on!", level="warning")

        print("Log file at {}.".format(log_file))

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        try:
            print("Press ctrl-c to cancel at any time.")

            func(*args, **kwargs)

            pool.close()
            pool.join()
        except KeyboardInterrupt:
            log("Caught KeyboardInterrupt! Cleaning up and terminating workers. Please wait...", level="warning")
            pool.terminate()
            pool.join()
            gracefully_exit()
        except Exception:
            traceback.print_exc()
            log("An exception occured!", level="exception", stdout=False)
            pool.terminate()
            pool.join()
            gracefully_exit()

        log("SCRIPT DONE.", extra={"script_elapsed_sec": time.time() - start_time})

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
log_file = Path(SPLUNK_HOME + "/var/log/splunk/" + script_filename + ".log")

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
