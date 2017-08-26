#!/usr/bin/env python3
#coding=utf-8
import os
import sys
import logging
import config

def daemon():
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        logging.error(e.strerror + "\n" + "Fork Failed")
        sys.exit(1)

    #os.chdir("/")
    os.umask(0)
    os.setsid()

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        logging.error(e.strerror + "\n" + "Fork Failed")
        sys.exit(1)
