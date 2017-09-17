#!/usr/bin/python
# coding: utf8

__version__ = '0.2'

import logging
import struct
import time
from threading import Thread
import codecs
from PyCRC.CRCCCITT import CRCCCITT


logger = logging.getLogger(__name__)


def calcCRC(data, little_endian=False):
    format_char = ">H"

    crc = CRCCCITT("FFFF").calculate(bytes(data))
    if little_endian:
        format_char = "<H"

    b = bytearray(struct.pack(format_char, crc))
    return b

class Frame(object):
    STATE_READ = 0x01
    STATE_ESCAPE = 0x02

    def __init__(self, little_endian = False):
        self.finished = False
        self.error = False
        self.state = self.STATE_READ
        self.data = bytearray()
        self.crc = bytearray()
        self.reader = None
        self.little_endian = little_endian

    def __len__(self):
        return len(self.data)

    def addByte(self, b):
        if b == 0x7D:
            self.state = self.STATE_ESCAPE
        elif self.state == self.STATE_ESCAPE:
            self.state = self.STATE_READ
            b = b ^ 0x20
            self.data.append(b)
        else:
            self.data.append(b)

    def finish(self):
        self.crc = self.data[-2:] #bytearray([self.data[-1], self.data[-2]])
        self.data = self.data[:-2]
        self.finished = True

    def checkCRC(self):
        res = bool(self.crc == calcCRC(self.data, self.little_endian))
        if not res:
            c1 = codecs.encode(self.crc, "hex")
            c2 =  codecs.encode(calcCRC(self.data, self.little_endian), "hex")
            logger.warning("invalid crc %s != %s",c1 ,c2)
            self.error = True
        return res

    def toString(self):
        return str(self.data)


class HDLC(object):
    def __init__(self, serial, little_endian=False):
        self.serial = serial
        self.current_frame = None
        self.last_frame = None
        self.frame_callback = None
        self.error_callback = None
        self.running = False
        self.little_endian = little_endian

    @classmethod
    def toBytes(cls, data):
        return bytearray(data)

    def sendFrame(self, data):
        bs = self._encode(self.toBytes(data))
        logger.info("Sending Frame: %s", codecs.encode(bs, "hex"))
        res = self.serial.write(bs)
        logger.info("Send %s bytes", res)

    def _onFrame(self, frame):
        self.last_frame = frame
        s = self.last_frame.data
        logger.info("Received Frame: %s", codecs.encode(s, "hex"))
        if self.frame_callback is not None:
            self.frame_callback(s)

    def _onError(self, frame):
        self.last_frame = frame
        s = self.last_frame.toString()
        logger.warning("Frame Error: %s", codecs.encode(frame.data, "hex"))
        if self.error_callback is not None:
            self.error_callback(s)

    def _readBytes(self, size):
        while size > 0:
            b = bytearray(self.serial.read(1))
            if len(b) < 1:
                return False
            res = self._readByte(b[0])
            if res:
                return True

    def _readByte(self, b):
        assert 0 <= b <= 255
        if b == 0x7E:
            # Start or End
            if not self.current_frame or len(self.current_frame) < 1:
                # Start
                self.current_frame = Frame(little_endian=self.little_endian)
            else:
                # End
                self.current_frame.finish()
                self.current_frame.checkCRC()
        elif self.current_frame is None:
            # Ignore before Start
            return False
        elif not self.current_frame.finished:
            self.current_frame.addByte(b)
        else:
            # Ignore Bytes
            pass

        # Validate and return
        if self.current_frame.finished and not self.current_frame.error:
            # Success
            self._onFrame(self.current_frame)
            self.current_frame = None
            return True
        elif self.current_frame.finished:
            # Error
            self._onError(self.current_frame)
            self.current_frame = None
            return True
        return False

    def readFrame(self, timeout=5):
        timer = time.time() + timeout
        while time.time() < timer:
            i = self.serial.in_waiting
            if i < 1:
                time.sleep(0.0001)
                continue

            res = self._readBytes(i)

            if res:
                # Validate and return
                if not self.last_frame.error:
                    # Success
                    s = self.last_frame.toString()
                    return s
                elif self.last_frame.finished:
                    # Error
                    raise ValueError("Invalid Frame (CRC FAIL)")
        raise RuntimeError("readFrame timeout")

    # @classmethod ? not using cls why was this a classmethod maybe the author
    # was thinking @staticmethod?
    def _encode(self, bs):
        data = bytearray()
        data.append(0x7E)
        crc = calcCRC(bs, self.little_endian)
        bs = bs + crc
        for byte in bs:
            if byte == 0x7E or byte == 0x7D:
                data.append(0x7D)
                data.append(byte ^ 0x20)
            else:
                data.append(byte)
        data.append(0x7E)
        return bytes(data)

    def _receiveLoop(self):
        while self.running:
            i = self.serial.in_waiting
            if i < 1:
                time.sleep(0.001)
                continue
            res = self._readBytes(i)

    def startReader(self, onFrame, onError=None):
        if self.running:
            raise RuntimeError("reader already running")
        self.reader = Thread(target=self._receiveLoop)
        self.reader.setDaemon(True)
        self.frame_callback = onFrame
        self.error_callback = onError
        self.running = True
        self.reader.start()

    def stopReader(self):
        self.running = False
        self.reader.join()
        self.reader = None
