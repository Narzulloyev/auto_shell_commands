"""
    Original source : https://gist.github.com/darvell/dfe334d22f0bbae836644ef85ff1ff6e 
    I have edited the code above.
    I removed the redundant part of the code, changed some broken parts.

    How to use cod?
    $ python3 wireguard_log_reader_for_windows.py "C:\Program Files\WireGuard\Data\log.bin" > output_log.txt

"""
from ctypes import *
from datetime import datetime
import os
import sys

MAX_LOG_LINE_LENGTH = 512
MAX_LINES = 2048
MAGIC = 0xBADBABE

class LOGLINE(Structure):
    _fields_ = [("timeNs", c_int64), ("line", c_char * (MAX_LOG_LINE_LENGTH))]

class HEADER(Structure):
    _fields_ = [("magic", c_uint), ("lineCount", c_uint)]

def read_log(filepath):
    with open(filepath, 'rb') as f:
        header = HEADER()
        f.readinto(header)

        if header.magic != MAGIC:
            return

        for lineIndex in range(0, header.lineCount):
            try:
                line = LOGLINE()
                f.readinto(line)
            except:
                break
            if len(line.line) == 0:
                break
            timestamp = datetime.fromtimestamp(line.timeNs // 1000000000)
            print("{0} {1}".format(timestamp, line.line.decode('utf-8')))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        log_path = sys.argv[1]
        read_log(log_path)

