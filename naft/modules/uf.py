#!/usr/bin/env python3

__description__ = "Network Appliance Forensic Toolkit - Utility Functions"
__version__ = "1.0.1"
__original_author__ = "Didier Stevens"
__current_authors__ = "@digitalsleuth and @G-K7"
__date__ = "2026/06/15"

import time
import os
import zipfile
import sys
from concurrent.futures import ProcessPoolExecutor
from dateutil import parser as duparser
from zoneinfo import ZoneInfo

MALWARE_PASSWORD = "infected"
COMMON_TZS = {
    "UTC": ZoneInfo("UTC"),
    "GMT": ZoneInfo("GMT"),
    "Z": ZoneInfo("UTC"),
    "AEST": ZoneInfo("Australia/Sydney"),
    "AEDT": ZoneInfo("Australia/Sydney"),
    "ACST": ZoneInfo("Australia/Adelaide"),
    "ACDT": ZoneInfo("Australia/Adelaide"),
    "AWST": ZoneInfo("Australia/Perth"),
    "AWDT": ZoneInfo("Australia/Perth"),
    "EST": ZoneInfo("America/New_York"),     # Eastern Standard
    "EDT": ZoneInfo("America/New_York"),     # Eastern Daylight
    "CST": ZoneInfo("America/Chicago"),      # Central Standard ambiguous with China and Cuba Standard
    "CDT": ZoneInfo("America/Chicago"),      # Central Daylight
    "MST": ZoneInfo("America/Denver"),       # Mountain Standard
    "MDT": ZoneInfo("America/Denver"),       # Mountain Daylight
    "PST": ZoneInfo("America/Los_Angeles"),  # Pacific Standard
    "PDT": ZoneInfo("America/Los_Angeles"),  # Pacific Daylight
    "AKST": ZoneInfo("America/Anchorage"),   # Alaska Standard
    "AKDT": ZoneInfo("America/Anchorage"),   # Alaska Daylight
    "HST": ZoneInfo("Pacific/Honolulu"),     # Hawaii Standard
    "AST": ZoneInfo("America/Halifax"),      # Atlantic Standard ambiguous with Arabia Standard
    "ADT": ZoneInfo("America/Halifax"),      # Atlantic Daylight
    "WET": ZoneInfo("Europe/London"),        # Western European
    "WEST": ZoneInfo("Europe/London"),       # Western European Summer
    "BST": ZoneInfo("Europe/London"),        # British Summer
    "CET": ZoneInfo("Europe/Paris"),         # Central European
    "CEST": ZoneInfo("Europe/Paris"),        # Central European Summer
    "EET": ZoneInfo("Europe/Athens"),        # Eastern European
    "EEST": ZoneInfo("Europe/Athens"),       # Eastern European Summer
    "MSK": ZoneInfo("Europe/Moscow"),        # Moscow Time
    "JST": ZoneInfo("Asia/Tokyo"),           # Japan Standard
    "KST": ZoneInfo("Asia/Seoul"),           # Korea Standard
    "IST": ZoneInfo("Asia/Kolkata"),         # Indian Standard ambiguous with Irish and Israel Standard
    "SGT": ZoneInfo("Asia/Singapore"),       # Singapore Time
    "HKT": ZoneInfo("Asia/Hong_Kong"),       # Hong Kong Time
}

def InProgress(function, *args):
    animation = "|/-\\"
    idx = 0
    pool = ProcessPoolExecutor(3)
    future = pool.submit(function, *args)
    while not future.done():
        print(
            f"Processing... {animation[idx % len(animation)]}",
            end="\r",
            file=sys.stderr,
        )
        idx += 1
        time.sleep(0.1)
    return future.result()


def IsZIPFile(filename):
    filename = os.path.basename(filename)
    return filename.lower().endswith(".zip")


def File2Data(filename):
    try:
        if IsZIPFile(filename):
            with zipfile.ZipFile(filename, "r") as oZipfile:
                with oZipfile.open(
                    oZipfile.infolist()[0], "r", MALWARE_PASSWORD
                ) as oZipContent:
                    return oZipContent.read()
        else:
            with open(filename, "rb") as f:
                return f.read()
    except MemoryError:
        return MemoryError
    except:
        return None


def Data2File(data, filename, path):
    try:
        full_path = os.path.join(path, filename)
        f = open(full_path, "wb")
    except:
        return False
    with f:
        f.write(data)
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
                dStrings[iterant] = data[iStringStart : iterant + 1]
        elif iStringStart != -1:
            if iterant - iStringStart >= MIN_LENGTH:
                dStrings[iterant] = data[iStringStart:iterant]
            iStringStart = -1
    return dStrings


def DumpBytes(memory, baseAddress, WIDTH=16):
    lineHex = ""
    lineASCII = ""
    for iterant in range(len(memory)):
        lineHex += f"{memory[iterant]:02X} "
        if chr(memory[iterant]) >= "\x20" and chr(memory[iterant]) <= "\x7f":
            lineASCII += chr(memory[iterant])
        else:
            lineASCII += "."
        if iterant % WIDTH == WIDTH - 1:
            print(
                f" {int(baseAddress + iterant / WIDTH * WIDTH):08X}: {lineHex} {lineASCII}"
            )
            lineHex = ""
            lineASCII = ""
    if lineHex != "":
        lineHex += " " * (48 - len(lineHex))
        print(
            f" {int(baseAddress + iterant / WIDTH * WIDTH):08X}: {lineHex} {lineASCII}"
        )


def FindAllStrings(string, search):
    indices = []
    index = string.find(search)
    while index >= 0:
        indices.append(index)
        index = string.find(search, index + 1)
    return indices


def cn(value, output_format=None):
    if value is None:
        return "Not found"
    if output_format is None:
        return value
    return output_format.format(value)


def Timestamp(epoch=None):
    if epoch is None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return time.strftime("%Y%m%d-%H%M%S", localTime)


def LogLine(line):
    print(f"{Timestamp()}: {line}")


def ParseDateTime(dtg_str, time_format=None, tzinfos=COMMON_TZS):
    if dtg_str is None:
        return "No date found"
    parsed_date = duparser.parse(dtg_str, tzinfos=tzinfos)
    if time_format is None:
        return parsed_date
    return parsed_date.strftime(time_format)


class cBufferFile:

    def __init__(self, filename, buffersize, bufferoverlapsize):
        self.filename = filename
        self.buffersize = buffersize
        self.bufferoverlapsize = bufferoverlapsize
        self.fIn = None
        self.err = False
        self.index = None
        self.buffer = None
        self.filesize = os.path.getsize(self.filename)
        self.bytesread = 0

    def Read(self):
        if self.fIn is None:
            try:
                self.fIn = open(self.filename, "rb")
            except:
                self.err = True
                return False

        try:
            if self.index is None:
                self.index = 0
                self.buffer = self.fIn.read(self.buffersize + self.bufferoverlapsize)
            else:
                self.buffer = self.buffer[-self.bufferoverlapsize :]
                tempBuffer = self.fIn.read(self.buffersize)
                if not tempBuffer:
                    self.fIn.close()
                    return False
                self.buffer += tempBuffer
                self.index += self.buffersize
                self.bytesread += len(tempBuffer)
                return True

            if not self.buffer:
                self.fIn.close()
                return False
            self.bytesread += len(self.buffer)
            return True

        except MemoryError:
            self.fIn.close()
            self.err = MemoryError
            return False
        except:
            self.fIn.close()
            self.err = True
            return False

    def Progress(self):
        return int(float(self.bytesread) / float(self.filesize) * 100.0)
