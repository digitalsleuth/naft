#!/usr/bin/env python3

__description__ = 'Network Appliance Forensic Toolkit - Utility Functions'
__version__ = '1.0.1'
__original_author__ = 'Didier Stevens'
__current_authors__ = '@digitalsleuth and @G-K7'
__date__ = '2026/06/14'

import time
import os
import zipfile
import sys
from concurrent.futures import ProcessPoolExecutor
from dateutil import parser as duparser

MALWARE_PASSWORD = 'infected'


def InProgress(function, *args):
    animation = "|/-\\"
    idx = 0
    pool = ProcessPoolExecutor(3)
    future = pool.submit(function, *args)
    while not future.done():
        print("Processing... {}".format(animation[idx % len(animation)]), end="\r", file=sys.stderr)
        idx += 1
        time.sleep(0.1)
    return future.result()


def IsZIPFile(filename):
    filename = os.path.basename(filename)
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
    for iterant in range(size):
        if data[iterant] >= 20 and data[iterant] <= 127:
            if iStringStart == -1:
                iStringStart = iterant
            elif iterant + 1 == size and iterant - iStringStart + 1 >= MIN_LENGTH:
                dStrings[iterant] = data[iStringStart:iterant + 1]
        elif iStringStart != -1:
            if iterant - iStringStart >= MIN_LENGTH:
                dStrings[iterant] = data[iStringStart:iterant]
            iStringStart = -1
    return dStrings


def DumpBytes(memory, baseAddress, WIDTH=16):
    lineHex = ''
    lineASCII = ''
    for iterant in range(len(memory)):
        lineHex += '{:02X} '.format(memory[iterant])
        if chr(memory[iterant]) >= '\x20' and chr(memory[iterant]) <= '\x7F':
            lineASCII += chr(memory[iterant])
        else:
            lineASCII += '.'
        if iterant % WIDTH == WIDTH - 1:
            print(' {:08X}: {} {}'.format(int(baseAddress + iterant / WIDTH * WIDTH), lineHex, lineASCII))
            lineHex = ''
            lineASCII = ''
    if lineHex != '':
        lineHex += ' ' * (48 - len(lineHex))
        print(' {:08X}: {} {}'.format(int(baseAddress + iterant / WIDTH * WIDTH), lineHex, lineASCII))


def FindAllStrings(string, search):
    indices = []
    index = string.find(search)
    while index >= 0:
        indices.append(index)
        index = string.find(search, index + 1)
    return indices


def cn(value, output_format = None):
    if value is None:
        return 'Not found'
    if output_format is None:
        return value
    return output_format.format(value)


def Timestamp(epoch=None):
    if epoch is None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return time.strftime('%Y%m%d-%H%M%S', localTime)


def LogLine(line):
    print('{}: {}'.format(Timestamp(), line))


def ParseDateTime(dtg_str, time_format=None):
    if dtg_str is None:
        return 'No date found'
    parsed_date = duparser.parse(dtg_str)
    if time_format is None:
        return parsed_date
    return parsed_date.strftime(time_format)


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
        if self.fIn is None:
            try:
                self.fIn = open(self.filename, 'rb')
            except:
                self.error = True
                return False
        if self.index is None:
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
            return True
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
