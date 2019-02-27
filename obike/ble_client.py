#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bluepy import btle
from hexdump import hexdump
from collections import deque
from colorama import Back, Fore, Style
import struct
import time


class BleClient(object):

    def __init__(self, mac, iface=None):
        self.mac = mac
        self.iface = iface
        self.peripheral = None
        self.buffer = deque()

    def connect(self):
        self.peripheral = btle.Peripheral(self.mac, iface=self.iface)
        self.peripheral.setDelegate(self.MyDelegate(self.buffer))
        self.peripheral.writeCharacteristic(0x0036, "\x01\x00")

    def disconnect(self):
        self.peripheral.disconnect()

    class MyDelegate(btle.DefaultDelegate):
        def __init__(self, buffer):
            print "MyDelegate registered"
            self.buffer = buffer
            btle.DefaultDelegate.__init__(self)

        def handleNotification(self, cHandle, data):
            # print "Notification from 0x%04x:" % cHandle
            # hexdump(data)
            self.buffer.append(data)

    def __chunks(self, l, n):
        """Yield successive n-sized chunks from l."""
        for i in range(0, len(l), n):
            yield l[i:i+n]

    def _write(self, data):
        """ low level ble write """
        self.buffer.clear()
        print Fore.RED + "Writing data..." + Back.RED + Style.BRIGHT
        hexdump(data)
        print Style.RESET_ALL
        parts = self.__chunks(data, 19)
        for part in parts:
            self.peripheral.writeCharacteristic(0x0035, part)

        while self.peripheral.waitForNotifications(0.5):
            continue
        print Fore.GREEN + "Received data:" + Back.GREEN + Style.BRIGHT
        hexdump(''.join(self.buffer))
        print Style.RESET_ALL
        return ''.join(self.buffer)

    def _write_cmd(self, cmd, payload):
        """ write obike cmd """
        chksum = reduce(lambda x, y: chr(ord(x) ^ ord(y)), chr(cmd)+payload)
        length = len(payload)
        buffer = "\x67\x74" + chr(length) + chr(cmd) + payload + chksum
        return self._write(buffer)

    def _get_bike_id(self):
        """Returns the oBike identifier,
        i.e. the MAC address without the first 3 digits.
        """
        return self.mac.replace(':', '')[3:].upper()

    def _parse_lock_record(self, data):
        """Returns a dict containing the parsed values of 
        a lock record.
        """
        result = {
            "bytes": data.encode('hex'),
            "member_id": data[4:10].encode("hex"),
            "timestamp": struct.unpack(">I", data[10:14])[0],
            "obike_id": data[14:23],
            "timestamp_2": struct.unpack("<I", data[23:27])[0],
            "transaction_type": ord(data[27]),
            "latitude": data[28:40],
            "longitude": data[40:52],
            "mac_key": data[52:68].encode("hex"),
            "kex_index": ord(data[68]),
            "unknown": data[69:72].encode("hex"),
            "battery_level": struct.unpack("<H", data[72:74])[0] / 100.0
        }
        return result

    def get_lock_record(self):
        """Return the lock record, a data record persisted by the chip.
        Command type 0x86
        """
        print "[+] get_lock_record (0x86)"
        data = self._write_cmd(0x86, "")
        return self._parse_lock_record(data)

    def delete_lock_record(self, timestamp, bike_id=None):
        """Delete the lock record.
        Command type 0x86
        """
        print "[+] delete_lock_record (0x86)"
        if not bike_id:
            bike_id = self._get_bike_id()
        buf = bytes(struct.pack('>I', timestamp)) + bytes(bike_id)
        data = self._write_cmd(0x86, buf)
        return self._parse_lock_record(data)

    def get_challenge(self, lat=None, lng=None):
        """Get a challenge.
        Command type 0x81
        """
        print "[+] get_challenge (0x81)"
        buf = ""
        if lat and lng:
            buf = "%010.7f%09.6f" % (lat, lng)
        data = self._write_cmd(0x81, buf)
        result = {
            "bytes": data.encode('hex'),
            "unknown_1": data[4:8].encode('hex'),
            "challenge": data[8:12].encode('hex').upper(),
            "battery_level": struct.unpack("<H", data[12:14])[0] / 100.0,
            "unknown_2": ord(data[14])
        }
        return result

    def send_response(self, enc_key, timestamp, keys):
        """Send the response.
        Command type 0x82
        """
        print "[+] send_response (0x82)"
        buffer = chr(enc_key) + \
            "\x00\x01\x23\x45\x67\x89\x00" + \
            struct.pack('<I', timestamp) + \
            keys[0:12]
        result = self._write_cmd(0x82, buffer)

    def reset(self):
        """Reset the chip.
        Command type 0x86
        """
        print "[+] reset (0x89)"
        result = self._write_cmd(0x89, "")
