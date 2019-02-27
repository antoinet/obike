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

    def _get_bike_no(self):
        """Returns the oBike identifier,
        i.e. the MAC address without the first 3 digits.
        """
        return self.mac.replace(':', '')[3:].upper()

    def get_lock_record(self):
        """Return the lock record, a data record persisted by the chip.
        Command type 0x86
        """
        print "[+] get_lock_record (0x86)"
        return self._write_cmd(0x86, "")

    def delete_lock_record(self, timestamp):
        """Delete the lock record.
        Command type 0x86
        """
        print "[+] delete_lock_record (0x86)"
        buffer = bytes(struct.pack('>I', timestamp)) + \
            bytes(self._get_bike_no())
        result = self._write_cmd(0x86, buffer)

    def get_challenge(self, lat, lng):
        """Get a challenge.
        Command type 0x81
        """
        print "[+] get_challenge (0x81)"
        buffer = "%010.7f%09.6f" % (lat, lng)
        result = self._write_cmd(0x81, buffer)
        return result[8:12]

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
