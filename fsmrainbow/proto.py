# -*- coding: utf-8 -*-
import sys
import socket
import select
import logging
from time import time,sleep
from struct import pack, unpack

from fsmsock.proto import TcpTransport

class RainbowTcpClient(TcpTransport):
    def __init__(self, host, interval, cmds):
        self._host = host
        self._port = 5843
        self._interval = interval
        self._mininterval = interval
        self._from = 0x3ff
        self._cmds = cmds
        super().__init__(host, interval, (socket.AF_INET, socket.SOCK_STREAM, self._port))

    def __crc(self, data):
        crc = 0
        for c in data:
           crc ^= ord(c)
        return '%02X' % crc

    def _build_buf(self):
        self._res = {}
        self._buf = []
        self._bufidx = 0
        for r in self._cmds:
            req = '@%03X%03X%03X00000' % (r[0] & 0xfff, self._from & 0xfff, r[1] & 0xfff)
            self._res[r[0] << 24 | r[1]] = r
            req = "{}{}*\r\n".format(req, self.__crc(req))
            self._buf.append(bytes(req, 'ascii'))

    def send_buf(self):
        if not len(self._buf):
            return 0
        return self._write(self._buf[self._bufidx])

    def process_data(self, datain, tm = None):
        self._retries = 0
        if not datain:
            return 0
        if tm is None:
            tm = time()

        data = str(datain, 'ascii')

        if data[0] != '@':
            logging.critical('Wrong PKT start: {}'.format(data[0]))
            return 0

        calculated_crc = self.__crc(data[:-4])
        if calculated_crc != data[-4:-2]:
            logging.critical('Wrong CRC: {} expected {}'.format(calculated_crc, data[-4:-2]))
            return 0

        dest = int(data[1:4], 16)
        src = int(data[4:7], 16)
        cmd = int(data[7:10], 16)
        if dest != self._from:
            logging.warning('Wrong destination received {}'.format(dest))
            return 0

        size = int(data[13:15], 16) << 1
        try:
            data = data[15:-4]
            if len(data) != size:
                logging.warning('Wrong data length: {} expected: {}'.format(len(data), size))
                return 0
            self.on_data(self._res[src << 24 | cmd], data, tm)
        except Exception as e:
            print('ERR: {}.{}:{}: {}'.format(src, cmd, e, data))
            return 0


        self._bufidx = (self._bufidx + 1) % len(self._buf)
        self._state = self.READY
        if self._bufidx == 0:
            self.stop()
            return 0

        return select.EPOLLOUT

    def on_data(self, points, response, tm):
        print(tm, points, response)

def main():
    cfg = {
        'host': '172.19.0.49',
        'interval': 3.0,
        'cmds': [
            [ 0x001, 0x006, {} ],
            [ 0x002, 0x006, {} ]
        ]
    }
    from fsmsock import async
    c = RainbowTcpClient(**cfg)
    fsm = async.FSMSock()
    fsm.connect(c)
    while fsm.run():
        fsm.tick()

if __name__ == '__main__':
    main()
