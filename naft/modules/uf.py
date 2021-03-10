#!/usr/bin/env python3

__description__ = 'Network Appliance Forensic Toolkit - Utility Functions'
__version__ = '1.0.0b1'
__original_author__ = 'Didier Stevens'
__current_authors__ = '@digitalsleuth and @G-K7'
__date__ = '2021/03/05'

import time
import os
import zipfile
import sys
import datetime as dt
import re

MALWARE_PASSWORD = 'infected'

def IsZIPFile(filename):
    return filename.lower().endswith('.zip')


def File2Data(filename):
    if IsZIPFile(filename):
        oZipfile = zipfile.ZipFile(filename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', MALWARE_PASSWORD)
        try:
            return oZipContent.read()
        except MemoryError:
            return MemoryError
        except:
            return None
        finally:
            oZipContent.close()
            oZipfile.close()

    try:
        f = open(filename, 'rb')
    except:
        return None
    try:
        return f.read()
    except MemoryError:
        return MemoryError
    except:
        return None
    finally:
        f.close()


def Data2File(data, filename, path):
    try:
        full_path = os.path.join(path, filename)
        f = open(full_path, 'wb')
    except:
        return False
    try:
        f.write(data)
    except:
        return False
    finally:
        f.close()
    return True


def SearchASCIIStrings(data, MIN_LENGTH=5):
    dStrings = {}
    iStringStart = -1
    size = len(data)
    for iter in range(size):
        if data[iter] >= 20 and data[iter] <= 127:
            if iStringStart == -1:
                iStringStart = iter
            elif iter + 1 == size and iter - iStringStart + 1 >= MIN_LENGTH:
                dStrings[iter] = data[iStringStart:iter + 1]
        elif iStringStart != -1:
            if iter - iStringStart >= MIN_LENGTH:
                dStrings[iter] = data[iStringStart:iter]
            iStringStart = -1
    return dStrings


def DumpBytes(memory, baseAddress, WIDTH=16):
    lineHex = ''
    lineASCII = ''
    for iter in range(len(memory)):
        lineHex += '{:02X} '.format(memory[iter])
        if chr(memory[iter]) >= '\x20' and chr(memory[iter]) <= '\x7F':
            lineASCII += chr(memory[iter])
        else:
            lineASCII += '.'
        if iter % WIDTH == WIDTH - 1:
            print(' {:08X}: {} {}'.format(int(baseAddress + iter / WIDTH * WIDTH), lineHex, lineASCII))
            lineHex = ''
            lineASCII = ''
    if lineHex != '':
        lineHex += ' ' * (48 - len(lineHex))
        print(' {:08X}: {} {}'.format(int(baseAddress + iter / WIDTH * WIDTH), lineHex, lineASCII))


def FindAllStrings(string, search):
    indices = []
    index = string.find(search)
    while index >= 0:
        indices.append(index)
        index = string.find(search, index + 1)
    return indices


def iif(booleanExpression, valueTrue, valueFalse):
    if booleanExpression:
        return valueTrue
    else:
        return valueFalse


def cn(value, format=None):
    if value == None:
        return 'Not found'
    elif format == None:
        return value
    else:
        return format % value


def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]


def LogLine(line):
    print('{}: {}'.format(Timestamp(), line))


class cBufferFile():
    def __init__(self, filename, buffersize, bufferoverlapsize):
        self.filename = filename
        self.buffersize = buffersize
        self.bufferoverlapsize = bufferoverlapsize
        self.fIn = None
        self.error = False
        self.index = None
        self.buffer = None
        self.filesize = os.path.getsize(self.filename)
        self.bytesread = 0

    def Read(self):
        if self.fIn == None:
            try:
                self.fIn = open(self.filename, 'rb')
            except:
                self.error = True
                return False

        if self.index == None:
            self.index = 0
            try:
                self.buffer = self.fIn.read(self.buffersize + self.bufferoverlapsize)
                self.bytesread += len(self.buffer)
            except MemoryError:
                self.fIn.close()
                self.error = MemoryError
                return False
            except:
                self.fIn.close()
                self.error = True
                return False
            if self.buffer == '':
                self.fIn.close()
                return False
            else:
                return True
        else:
            self.buffer = self.buffer[-self.bufferoverlapsize:]
            try:
                tempBuffer = self.fIn.read(self.buffersize)
                if tempBuffer == '':
                    self.fIn.close()
                    return False
                self.buffer += tempBuffer
                self.index += self.buffersize
                self.bytesread += len(tempBuffer)
                return True
            except MemoryError:
                self.fIn.close()
                self.error = MemoryError
                return False
            except:
                self.fIn.close()
                self.error = True
                return False

    def Progress(self):
        return int(float(self.bytesread) / float(self.filesize) * 100.0)


months = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12
}

dtg_events = re.compile("([A-Za-z]{3})\s([\s\d]{2})\s(\d{2}):(\d{2}):(\d{2})\.(\d{3})")
dtg_hist = re.compile("(\d{2}):(\d{2}):(\d{2})\s([A-Z]+)\s([A-Za-z]+)\s([A-Za-z]{3})\s([\s\d]+)\s(\d{4})")


def parse_dtg(dtg_str):
    if dtg_hist.match(dtg_str):
        dtg = dtg_hist.match(dtg_str)
        return dt.datetime(int(dtg.group(8)), # Year
                            months[dtg.group(6)],  # Month
                            int(dtg.group(7)), #Day
                            int(dtg.group(1)),  # Hour
                            int(dtg.group(2)),  # Minutes
                            int(dtg.group(3)) # Seconds
                            )

    else:
        dtg = dtg_events.match(dtg_str[1:20])
        return (dt.datetime(dt.date.today().year,  # Current year
                            months[dtg.group(1)],  # Month
                            int(dtg.group(2)),  # Day
                            int(dtg.group(3)),  # Hour
                            int(dtg.group(4)),  # Minutes
                            int(dtg.group(5))  # Seconds
                            ), dtg.group(6))  # Milliseconds
