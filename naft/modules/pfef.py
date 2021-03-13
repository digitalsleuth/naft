#!/usr/bin/env python3

__description__ = 'Network Appliance Forensic Toolkit - Packet and Frame Extraction Functions'
__version__ = '1.0.0b1'
__original_author__ = 'Didier Stevens'
__current_authors__ = '@digitalsleuth and @G-K7'
__date__ = '2021/03/05'

import struct
import hashlib
import re


class cFrames():

    def __init__(self, ouiFilename=None):
        self.frames = []
        self.countFrames = 0
        self.countPackets = 0
        self.dHashes = {}
        self.ParseOUITXT(ouiFilename)
        self.dFilenameIndexLength = {}

    def AddFramePrivate(self, index, data, duplicates, filename=''):
        filenameIndexLength = '{}-{:d}-{:d}'.format(filename, index, len(data))
        if filenameIndexLength in self.dFilenameIndexLength:
            return False
        self.dFilenameIndexLength[filenameIndexLength] = True
        sha1Hash = hashlib.sha1(data).hexdigest()
        if sha1Hash not in self.dHashes:
            self.dHashes[sha1Hash] = 0
        self.dHashes[sha1Hash] += 1
        if duplicates or self.dHashes[sha1Hash] == 1:
            self.frames.append((index, data))
        return True

    def AddFrame(self, index, data, duplicates, filename=''):
        if self.dOUI == {} or data[0:3].hex() in self.dOUI or data[6:9].hex() in self.dOUI:
            if self.AddFramePrivate(index, data, duplicates, filename):
                self.countFrames += 1

    def AddIPPacket(self, index, data, duplicates, filename=''):
        if self.AddFramePrivate(index, b'\x00\x00\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00' + b'\x08\x00' + data, duplicates, filename):
            self.countPackets += 1

    def WritePCAP(self, filename):
        try:
            f = open(filename, 'wb')
        except:
            return False
        # Global header
        f.write(b'\xD4\xC3\xB2\xA1')  # magic number
        f.write(b'\x02\x00')          # major version number
        f.write(b'\x04\x00')          # minor version number
        f.write(b'\x00\x00\x00\x00')  # GMT to local correction
        f.write(b'\x00\x00\x00\x00')  # accuracy of timestamps
        f.write(b'\xFF\xFF\x00\x00')  # max length of captured packets, in octets
        f.write(b'\x01\x00\x00\x00')  # data link type
        for frame in sorted(self.frames, key=lambda x: x[0]):
            # Packet Header
            f.write(struct.pack('<I', int(frame[0] / 1000000)))         # timestamp seconds; set to address
            f.write(struct.pack('<I', int(frame[0] % 1000000)))         # timestamp microseconds; set to address
            f.write(struct.pack('<I', min(len(frame[1]), 0xFFFF)))      # number of octets of packet saved in file; limit to 0xFFFF for WireShark
            f.write(struct.pack('<I', min(len(frame[1]), 0xFFFF)))      # actual length of packet; limit to 0xFFFF for WireShark
            # Packet Data
            f.write(frame[1][0:0xFFFF])
        f.close()
        return True

    def ParseOUITXT(self, ouiFilename):
        self.dOUI = {}
        if ouiFilename is not None:
            oRe = re.compile('^([0-9a-f]{6})')
            try:
                fOUI = open(ouiFilename, 'r')
            except:
                return
            for line in fOUI.readlines():
                oMatch = oRe.search(line.lower())
                if oMatch:
                    self.dOUI[oMatch.group(1)] = line.strip('\n')
            fOUI.close()


# http://stackoverflow.com/questions/3949726/calculate-ip-checksum-in-python
def CarryAroundAdd(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def CalculateIPChecksum(data):
    s = 0
    for i in range(0, len(data), 2):
        s = CarryAroundAdd(s, data[i] + ((data[i+1]) << 8))
    return ~s & 0xffff


# search for bytes between 0x45 and 0x4F (depending flag options) and check if they are the start of an IPv4 header by calculating and comparing the checksum
def ExtractIPPackets(oFrames, baseAddress, data, options, duplicates, multiple, filename=''):
    found = False
    if options:
        maxHeader = 0x50
    else:
        maxHeader = 0x46
    for headerStart in range(0x45, maxHeader):
        index = 0
        while index != -1:
            index = data.find(headerStart, index)
            if index != -1:
                try:
                    potentialIPHeader = data[index:index + 4 * (data[index] - 0x40)]
                    if CalculateIPChecksum(potentialIPHeader) == 0:
                        packetLength = potentialIPHeader[2] * 0x100 + potentialIPHeader[3]
                        if data[index-2] == 8 and data[index-1] == 0:  # EtherType IP
                            # IPv4 packet is inside an Ethernet frame; store the Ethernet frame
                            if data[index-6] == 0x81 and data[index-5] == 0:  # 802.1Q, assuming no double tagging
                                oFrames.AddFrame(baseAddress + index - 2*6 - 4 - 2, data[index - 2*6 - 4 - 2:index + packetLength], duplicates, filename)
                                found = True
                            else:
                                oFrames.AddFrame(baseAddress + index - 2*6 - 2, data[index - 2*6 - 2:index + packetLength], duplicates, filename)
                                found = True
                        else:
                            # IPv4 packet is not inside an Ethernet frame; store the IPv4 packet
                            oFrames.AddIPPacket(baseAddress + index, data[index:index + packetLength], duplicates, filename)
                            found = True
                except:
                    pass
                index += 1
            if found and not multiple:
                return found
    return found


# search for ARP frames for Ethernet, they start with \x08\x06\x00\x01\x08\x00\x06\x04
def ExtractARPFrames(oFrames, baseAddress, data, duplicates, multiple, filename=''):
    found = False
    index = 0
    while index != -1:
        index = data.find(b'\x08\x06\x00\x01\x08\x00\x06\x04', index)  # https://en.wikipedia.org/wiki/Address_Resolution_Protocol
        if index != -1:
            oFrames.AddFrame(baseAddress + index - 2*6, data[index - 2*6:index + 30], duplicates, filename)
            found = True
            index += 1
        if found and not multiple:
            return found
    return found
