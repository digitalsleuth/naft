#!/usr/bin/env python3

__description__ = 'Network Appliance Forensic Toolkit - Generic Frame Extraction'
__version__ = '1.0.0b1'
__original_author__ = 'Didier Stevens'
__current_authors__ = '@digitalsleuth and @G-K7'
__date__ = '2021/03/05'

import glob
import struct
import naft.modules.impf as impf
import naft.modules.uf as uf
import naft.modules.pfef as pfef
import time

def ExtractIPPacketsFromFile(filenamesRawData, filenamePCAP, arguments):
    uf.LogLine('Start')
    if arguments['ouitxt'] == None:
        oFrames = pfef.cFrames()
    else:
        oFrames = pfef.cFrames(arguments['ouitxt'])
    countProcessedFiles = 0
    for filenameRawData in filenamesRawData:
        if arguments['buffer']:
            uf.LogLine('Buffering file {}'.format(filenameRawData))
            oBufferFile = uf.cBufferFile(filenameRawData, arguments['buffersize'] * 1024 * 1024, arguments['bufferoverlapsize'] * 1024 * 1024)
            while oBufferFile.Read():
                uf.LogLine('Processing buffer 0x{:x} size {:d} MB {:d}%'.format(oBufferFile.index, len(oBufferFile.buffer) / 1024 / 1024, oBufferFile.Progress()))
                uf.LogLine('Searching for IPv4 packets')
                pfef.ExtractIPPackets(oFrames, oBufferFile.index, oBufferFile.buffer, arguments['options'], arguments['duplicates'], True, filenameRawData)
                uf.LogLine('Searching for ARP Ethernet frames')
                pfef.ExtractARPFrames(oFrames, oBufferFile.index, oBufferFile.buffer, arguments['duplicates'], True, filenameRawData)
            if oBufferFile.error == MemoryError:
                uf.LogLine('Data is too large to fit in memory, use smaller buffer')
            elif oBufferFile.error:
                uf.LogLine('Error reading file')
            countProcessedFiles += 1
        else:
            uf.LogLine('Reading file {}'.format(filenameRawData))
            rawData = uf.File2Data(filenameRawData)
            if rawData == None:
                uf.LogLine('Error reading file')
            if rawData == MemoryError:
                uf.LogLine('File is too large to fit in memory')
            else:
                uf.LogLine('Searching for IPv4 packets')
                pfef.ExtractIPPackets(oFrames, 0, rawData, arguments['options'], arguments['duplicates'], True, filenameRawData)
                uf.LogLine('Searching for ARP Ethernet frames')
                pfef.ExtractARPFrames(oFrames, 0, rawData, arguments['duplicates'], True, filenameRawData)
                countProcessedFiles += 1

    if countProcessedFiles > 0:
        uf.LogLine('Writing PCAP file {}'.format(filenamePCAP))
        if not oFrames.WritePCAP(filenamePCAP):
            uf.LogLine('Error writing PCAP file')

        uf.LogLine('Number of identified frames:   {:5d}'.format(oFrames.countFrames))
        uf.LogLine('Number of identified packets:  {:5d}'.format(oFrames.countPackets))
        uf.LogLine('Number of frames in PCAP file: {:5d}'.format(len(oFrames.frames)))

    uf.LogLine('Done')

def IOSFrames(coredumpFilename, filenameIOMEM, filenamePCAP, arguments):
    uf.LogLine('Start')
    uf.LogLine('Reading file {}'.format(coredumpFilename))
    oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error != None:
        print(oIOSCoreDump.error)
        return
    uf.LogLine('Searching for heap region')
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap == None:
        print('Heap region not found')
        return
    oIOSMemoryParserHeap = impf.cIOSMemoryParser(memoryHeap)
    oIOSMemoryParserHeap.ResolveNames(oIOSCoreDump)
    uf.LogLine('Reading file {}'.format(filenameIOMEM))
    dataIOMEM = uf.File2Data(filenameIOMEM)
    uf.LogLine('Searching for base address from {}'.format(filenameIOMEM))
    oIOSMemoryParserIOMEM = impf.cIOSMemoryParser(dataIOMEM)
    addressIOMEM = oIOSMemoryParserIOMEM.baseAddress
    if addressIOMEM == None:
        print('Error parsing IOMEM')
        return
    oFrames = pfef.cFrames()
    if arguments['verbose']:
        print(impf.cIOSMemoryBlockHeader.ShowHeader)
    for oIOSMemoryBlockHeader in oIOSMemoryParserHeap.Headers:
        if oIOSMemoryBlockHeader.AllocNameResolved == '*Packet Header*':
            frameAddress = struct.unpack('>I', oIOSMemoryBlockHeader.GetData()[40:44])[0]
            frameSize = struct.unpack('>H', oIOSMemoryBlockHeader.GetData()[72:74])[0]
            if frameSize <= 1:
                frameSize = struct.unpack('>H', oIOSMemoryBlockHeader.GetData()[68:70])[0]
            if frameAddress != 0 and frameSize != 0:
                if arguments['verbose']:
                    print(oIOSMemoryBlockHeader.ShowLine())
                    uf.DumpBytes(dataIOMEM[frameAddress - addressIOMEM : frameAddress - addressIOMEM + frameSize], frameAddress)
                oFrames.AddFrame(frameAddress - addressIOMEM, dataIOMEM[frameAddress - addressIOMEM : frameAddress - addressIOMEM + frameSize], True)
    oFrames.WritePCAP(filenamePCAP)
    uf.LogLine('{:d} frames written to {}'.format(oFrames.countFrames, filenamePCAP))
    uf.LogLine('Done')
