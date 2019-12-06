#!/usr/bin/env python
# hobbes3

import requests
import os
import sys
import json
import inspect
import argparse
import toml
import logging
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import jsonlogger
from functools import wraps
from tqdm import tqdm
from argparse import ArgumentParser
from time import time, sleep
from io import StringIO
from random import uniform
from pathlib import Path
from secrets import token_urlsafe
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3.util.retry import Retry
from multiprocessing import Lock
from multiprocessing.dummy import Pool

def rest_wrapped(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            print("Press ctrl-c to cancel at any time.")
            logger.info("Script start.")

            lock = Lock()

            if partial_script_args.test:
                logger.info("Test mode is on!")
            if partial_script_args.sample:
                logger.info("Sample mode is on!")

            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

            func(*args, **kwargs)

            pool.close()
        except KeyboardInterrupt:
            logger.error("Caught KeyboardInterrupt! Cleaning up and terminating workers. Please wait...")
            pool.terminate()

            with lock:
                logger.error("Script incomplete!", extra={"script_elapsed_sec": time() - start_time})
                os._exit(1)
        finally:
            pool.join()

        logger.info("Script done!", extra={"script_elapsed_sec": time() - start_time})

    return wrapper

def retry_session(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504]):
    s = RetrySession()
    s.verify = False
    retries = Retry(total=total, backoff_factor=backoff_factor, status_forcelist=status_forcelist, method_whitelist=frozenset(["GET", "POST", "PUT"]))
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("http://", adapter)
    s.mount("https://", adapter)

    return s

class RetrySession(requests.Session):
    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def request(self, method, url, **kwargs):
        request_start_time = time()

        request_id = token_urlsafe(16)

        sleep_min = config["requests"]["sleep_min"]
        sleep_max = config["requests"]["sleep_max"]
        sleep_sec = uniform(sleep_min, sleep_max)

        meta = {
            "request_id": request_id,
        }

        sleep(sleep_sec)

        text_truncate = config["requests"]["text_truncate"]

        # https://stackoverflow.com/a/19476841/1150923
        # Create an empty class to do r.request_id later even if the request failed.
        r = type("", (), {})()
        try:
            m = meta.copy()
            m["sleep_sec"] = sleep_sec
            m["request"] = {
                "method": method,
                "url": url,
            }

            for k, v in kwargs.items():
                if k == "data":
                    data_size = len(v)
                    m["request"]["data_size"] = data_size
                    if data_size <= text_truncate:
                        m["request"]["data"] = v
                        m["request"]["data_truncated"] = False
                    else:
                        m["request"]["data"] = v[:text_truncate]+" ..."
                        m["request"]["data_truncated"] = True
                else:
                    m["request"][k] = v

            logger.debug("Request start.", extra=m)

            r = super().request(method, url, **kwargs)
        except:
            logger.warning("", exc_info=True, extra=meta)
        finally:
            m = meta.copy()
            m["request_elapsed_sec"] = time() - request_start_time
            m["response"] = {
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

            if hasattr(r, "text"):
                data_size = len(r.text)
                m["response"]["data_size"] = data_size
                if data_size <= text_truncate:
                    m["response"]["data"] = r.text
                    m["response"]["data_truncated"] = False
                else:
                    m["response"]["data"] = r.text[:text_truncate]+" ..."
                    m["response"]["data_truncated"] = True
            else:
                logger.warning("Empty response received!", extra=m)

            if r.status_code == 200:
                logger.debug("Response received.", extra=m)
            else:
                logger.warning("Response received but with non-OK status code!", extra=m)

            r.request_id = request_id

            return r

def multiprocess(func, arg_list):
    for _ in tqdm(pool.imap_unordered(func, arg_list), total=len(arg_list), disable=partial_script_args.silent):
        pass

def get_parent_file():
    filename = inspect.stack()[-1][1]
    parent_file = Path(filename).resolve()

    return parent_file

def get_config():
    # https://stackoverflow.com/a/24837438/1150923
    def merge_dicts(dict1, dict2):
        """ Recursively merges dict2 into dict1 """
        if not isinstance(dict1, dict) or not isinstance(dict2, dict):
            return dict2
        for k in dict2:
            if k in dict1:
                dict1[k] = merge_dicts(dict1[k], dict2[k])
            else:
                dict1[k] = dict2[k]
        return dict1

    parent_file = get_parent_file()
    app_bin_path = parent_file.parents[0]

    toml_file_default = str(app_bin_path) + "/splunk_rest/config.toml"
    toml_file_local = str(app_bin_path) + "/config.toml"

    config_default = toml.load(toml_file_default)

    if Path(toml_file_local).exists():
        config_local = toml.load(toml_file_local)
        # Merge default and local. Local overrides default.
        config = merge_dicts(config_default, config_local)
    else:
        logger.error("The local config file not found! The script will only use the default config file and will probably not run properly.", extra={"toml_file_local": toml_file_local, "toml_file_default": toml_file_default})
        config = config_default

    return config

def get_partial_script_args():
    # Command line arguments.
    arg_parser = ArgumentParser(add_help=False)
    arg_parser.add_argument("--silent", action="store_true", help="silent mode (suppresses stdout for Splunk scripted inputs)")
    arg_parser.add_argument("--test", action="store_true", help="test mode (typically send only to the main index)")
    arg_parser.add_argument("--sample", action="store_true", help="sample mode (typically reduces the number of API calls)")
    partial_script_args = arg_parser.parse_known_args()[0]

    return arg_parser, partial_script_args

def get_script_args():
    # Manually create the default help message since using parse_known_args() won't capture additional arguments created by the main script.
    arg_parser.add_argument("--help", action="store_true", help="show this help message and exit")
    script_args = arg_parser.parse_args()

    if script_args.help:
        arg_parser.print_help()
        sys.exit()

    logger.debug("Command line arguments.", extra=vars(script_args))

    print("Log file at {}.".format(log_file))
    print("Session id: {}".format(session_id))

    return script_args

def configure_logger():
    # https://stackoverflow.com/a/57820456/1150923
    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.session_id = session_id
        return record

    # https://stackoverflow.com/a/8163115/1150923
    class LogLevelFilter():
        def __init__(self, level_list):
            self.level_list = level_list

        def filter(self, logRecord):
            return logRecord.levelno in self.level_list

    parent_file = get_parent_file()
    # parent_filename is without the file extension, ie without ".py".
    parent_filename = parent_file.stem

    # Save logs the Splunk directory to be picked up by `index=_internal`.
    splunk_home = config["logging"]["splunk_home"]
    log_file = Path(splunk_home + "/var/log/splunk/" + parent_filename + ".log")

    old_factory = logging.getLogRecordFactory()
    logging.setLogRecordFactory(record_factory)

    json_format = jsonlogger.JsonFormatter("(asctime) (levelname) (threadName) (session_id) (pathname) (lineno) (funcName) (message)")
    std_format = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    # Logging to rotated files for Splunk.
    # Log every level to files.
    rotation_bytes = config["logging"]["rotation_mb"] * 1024 * 1024
    rotation_limit = config["logging"]["rotation_limit"]
    file_handler = RotatingFileHandler(log_file, maxBytes=rotation_bytes, backupCount=rotation_limit)
    file_handler.setFormatter(json_format)
    file_handler.setLevel(logging.DEBUG)

    # Logging to stdout for command line.
    # Log only INFO, ERROR, and CRITICAL levels to stdout.
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(std_format)
    console_handler.setLevel(logging.DEBUG)
    console_handler.addFilter(LogLevelFilter([logging.INFO, logging.ERROR, logging.CRITICAL]))

    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    if not partial_script_args.silent:
        logger.addHandler(console_handler)

    return log_file

session_id = token_urlsafe(8)
start_time = time()
config = get_config()
arg_parser, partial_script_args = get_partial_script_args()

if partial_script_args.silent:
    sys.stdout = StringIO()

logger = logging.getLogger(__name__)
log_file = configure_logger()

pool = Pool(config["general"]["threads"])
