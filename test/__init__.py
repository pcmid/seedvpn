#import
import os
import sys
import getopt
import fcntl
import time
import struct
import socket
import select
import logging
import configparser
from copy import deepcopy
from IPy import IP
from Crypto.Cipher import AES

#error code define
ARGS_ERROR = 1
NETWORK_ERROR = 2
PASSWD_ERROR = 3
LOGIN_TIMEOUT = 4
