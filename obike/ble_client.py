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

    def chunks(self, l, n):
        """Yield successive n-sized chunks from l."""
        for i in range(0, len(l), n):
            yield l[i:i+n]

    def write(self, data):
        """ low level ble write """
        self.buffer.clear()
        print Fore.RED + "Writing data..." + Back.RED + Style.BRIGHT
        hexdump(data)
        print Style.RESET_ALL
        parts = self.chunks(data, 19)
        for part in parts:
            self.peripheral.writeCharacteristic(0x0035, part)

        while self.peripheral.waitForNotifications(0.5):
            continue
        print Fore.GREEN + "Received data:" + Back.GREEN + Style.BRIGHT
        hexdump(''.join(self.buffer))
        print Style.RESET_ALL
        return ''.join(self.buffer)

    def write_cmd(self, cmd, payload):
        """ write obike cmd """
        chksum = reduce(lambda x, y: chr(ord(x) ^ ord(y)), chr(cmd)+payload)
        length = len(payload)
        buffer = "\x67\x74" + chr(length) + chr(cmd) + payload + chksum
        return self.write(buffer)

    def hello(self):
        print "Hello..."
        return self.write_cmd(0x86, "")

    def hello_lock_bike(self, timestamp):
        print "Hello lock bike..."
        buffer = bytes(struct.pack('>I', timestamp)) + \
            bytes(self.mac.replace(':', '')[3:].upper())
        result = self.write_cmd(0x86, buffer)

    def push_coords(self, lat, lng):
        print "Push coords..."
        buffer = "%010.7f%09.6f" % (lat, lng)
        result = self.write_cmd(0x81, buffer)

        # assert result[0:2] == "\x67\x74"
        # assert result[3] == "\x41"
        # assert result[4:8] == "\x00\x11\x51\x00"
        return result[8:12]

    def send_keys(self, enc_key, timestamp, keys):
        print "Send keys..."
        buffer = chr(enc_key) + \
            "\x00\x01\x23\x45\x67\x89\x00" + \
            struct.pack('<I', timestamp) + \
            keys[0:12]
        result = self.write_cmd(0x82, buffer)

    def reset(self):
        print "Reset chip"
        result = self.write_cmd(0x89, '')
