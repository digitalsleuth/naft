#!/usr/bin/env python3

__description__ = 'Network Appliance Forensic Toolkit - IOS Core Dumps'
__version__ = '1.0.0b1'
__original_author__ = 'Didier Stevens'
__current_authors__ = '@digitalsleuth and @G-K7'
__date__ = '2021/03/05'

import struct
import re
import sys
import os
import binascii
import naft.modules.uf as uf
import naft.modules.impf as impf
import naft.modules.pfef as pfef
import naft.modules.iipf as iipf

def IOSRegions(coredumpFilename, arguments):
    oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error != None:
        print(oIOSCoreDump.error)
    else:
        print('Start      End        Size       Name')
        for region in oIOSCoreDump.regions:
            if region[2] != None:
                print('0x{:08X} 0x{:08X} {:<10d} {}'.format(region[1], (region[1] + region[2] - 1), region[2], region[0]))
                if arguments['output']:
                    uf.Data2File(oIOSCoreDump.Region(region[0])[1], '{}-{}-0x{:08X}'.format(os.path.basename(coredumpFilename), region[0], region[1]), arguments['output'])
            else:
                print('0x{:08X} {} {}'.format(region[1], ' ' * 21, region[0]))
        addressBSS, dataBSS = oIOSCoreDump.RegionBSS()

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return [line.rstrip('\n') for line in f.readlines()]
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading {}'.format(argument))
        else:
            return strings
    else:
        return [argument]

def ProcessHeap(oIOSMemoryBlockHeader, arguments, coredumpFilename, wpath=None):
    if not arguments['strings']:
        print(oIOSMemoryBlockHeader.ShowLine())
    if arguments['strings']:
        dStrings = uf.SearchASCIIStrings(oIOSMemoryBlockHeader.GetData())
        if arguments['grep'] != '':
            printHeader = True
            for key, value in dStrings.items():
                if value.find(arguments['grep'].encode('utf-8')) >= 0:
                    if printHeader:
                        print(oIOSMemoryBlockHeader.ShowLine())
                        printHeader = False
                    print(' {:08X}: {}'.format(
                    oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.BlockSize + key, value.decode('utf-8')))
        elif arguments['minimum'] == 0 or len(dStrings) >= arguments['minimum']:
            #if arguments['verbose']:
            print(oIOSMemoryBlockHeader.ShowLine())
            for key, value in dStrings.items():
                print(' {:08X}: {}'.format(
                oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.BlockSize + key, value.decode('utf-8')))
    if arguments['dump']:
        uf.DumpBytes(oIOSMemoryBlockHeader.GetData(),
                          oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.headerSize)
    if arguments['dumpraw']:
        uf.DumpBytes(oIOSMemoryBlockHeader.GetRawData(), oIOSMemoryBlockHeader.address)
    if arguments['output']:
        uf.Data2File(oIOSMemoryBlockHeader.GetData(), '{}-heap-0x{:08X}.data'.format(coredumpFilename, oIOSMemoryBlockHeader.address), wpath)
        if arguments['verbose']:
            print('\tFile: {}{}-heap-0x{:08X}.data created.\n'.format(wpath, coredumpFilename, oIOSMemoryBlockHeader.address))

def IOSHeap(coredumpFilename, arguments):

    if arguments['output'] != None:
        wpath = os.path.join(arguments['output'], "heap_data")
        os.mkdir(wpath)
    else:
        wpath = ''

    oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error != None:
        print(oIOSCoreDump.error)
        return
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap == None:
        print('Heap region not found')
        return
    oIOSMemoryParser = impf.cIOSMemoryParser(memoryHeap)
    if arguments['resolve'] or arguments['filter'] != '':
        oIOSMemoryParser.ResolveNames(oIOSCoreDump)
    if arguments['filter'] == '':
        print(impf.cIOSMemoryBlockHeader.ShowHeader)
        for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
            ProcessHeap(oIOSMemoryBlockHeader, arguments, coredumpFilename, wpath)
    else:
        print(impf.cIOSMemoryBlockHeader.ShowHeader)
        for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
            if oIOSMemoryBlockHeader.AllocNameResolved == arguments['filter']:
                ProcessHeap(oIOSMemoryBlockHeader, arguments, coredumpFilename, wpath)

def IOSCWStringsSub(data):
    oCWStrings = impf.cCiscoCWStrings(data)
    if oCWStrings.error != None:
        print(oCWStrings.error)
        return
    keys = list(oCWStrings.dCWStrings.keys())
    keys.sort()
    for key in keys:
        if key == b'CW_SYSDESCR':
            print('{}:'.format(key.decode('utf-8')))
            print(oCWStrings.dCWStrings[key].decode('utf-8'))
        else:
            print('{}:{}{}'.format(key.decode('utf-8'), (' ' * (22 - len(key))), oCWStrings.dCWStrings[key].decode('utf-8')))

def IOSCWStrings(coredumpFilename, arguments):
    if arguments['raw']:
        coredump = uf.File2Data(coredumpFilename)
        if coredump == None:
            print('Error reading file {}'.format(coredumpFilename))
        else:
            IOSCWStringsSub(coredump)
    else:
        oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
        if oIOSCoreDump.error  != None:
            print(oIOSCoreDump.error)
            return
        addressData, memoryData = oIOSCoreDump.RegionDATA()
        if memoryData == None:
            print('Data region not found')
            return
        IOSCWStringsSub(memoryData)

def PrintStatsAnalysis(dStats, oIOSCoreDump):
    keys1 = list(dStats.keys())
    keys1.sort()
    for key1 in keys1:
        countKeys = len(dStats[key1])
        keys2 = list(dStats[key1].keys())
        keys2.sort()
        if countKeys > 2 and countKeys <= 7:
            bucket = '-> ' + ' '.join(['{:X}:{:d}'.format(key2, dStats[key1][key2]) for key2 in keys2])
        else:
            bucket = ''
        filtered = [x for x in dStats[key1] if x != 0]
        if filtered == []:
            filteredMin = min(dStats[key1])
        else:
            filteredMin = min(filtered)
        unfilteredMax = max(dStats[key1])
        regionNames = []
        for region in oIOSCoreDump.regions:
            if region[2] != None:
                if filteredMin >= region[1] and filteredMin <= region[1] + region[2] - 1:
                    if not region[0] in regionNames:
                        regionNames.append(region[0])
                if unfilteredMax >= region[1] and unfilteredMax <= region[1] + region[2] - 1:
                    if not region[0] in regionNames:
                        regionNames.append(region[0])
        regionNames.sort()
        regionName = ' '.join(regionNames).strip()
        print('{:3d} {:3X}: {:3d} {:08X} {:08X} {:08X} {} {}'.format(key1, key1*4, countKeys, min(dStats[key1]), filteredMin, unfilteredMax, regionName, bucket))

def IOSProcesses(coredumpFilename, arguments):
    oIOSCoreDumpAnalysis = impf.cIOSCoreDumpAnalysis(coredumpFilename)
    if oIOSCoreDumpAnalysis.error != None:
        print(oIOSCoreDumpAnalysis.error)
        return

    print(" PID QTy       PC Runtime (ms)    Invoked   uSecs    Stacks TTY StackBlk Process")
    for (processID, addressProcess, oIOSProcess) in oIOSCoreDumpAnalysis.processes:
        if arguments['filter'] == '' or processID == int(arguments['filter']):
            if oIOSProcess != None:
                if oIOSProcess.error == '':
                    line = oIOSProcess.Line()
                else:
                    line = '{:4d} {}'.format(processID, oIOSProcess.error)
                print(line)
                if arguments['dump']:
                    uf.DumpBytes(oIOSProcess.data, addressProcess)
            else:
                print(' {:>3d} {:08X} - addressProcess not found'.format(processID, addressProcess))

    if oIOSCoreDumpAnalysis.RanHeuristics:
        print('')
        print('*** WARNING ***')
        print('Unexpected process structure')
        print('Please reports these results')
        print('Fields determined with heuristics:')
        print('Process structure size: {:d}'.format(oIOSCoreDumpAnalysis.HeuristicsSize))
        keys = list(oIOSCoreDumpAnalysis.HeuristicsFields.keys())
        keys.sort(key=str.lower)
        for key in keys:
            value = oIOSCoreDumpAnalysis.HeuristicsFields[key]
            if value != None:
                print('{:-22s}: 0x{:04X}'.format(key, value[1]))

    if arguments['stats']:
        keys = list(oIOSCoreDumpAnalysis.dProcessStructureStats.keys())
        keys.sort()
        print('Number of different process structures: {:d}'.format(len(keys)))
        for index in keys:
            print('Process structures length: {:d}'.format(index))
            PrintStatsAnalysis(oIOSCoreDumpAnalysis.dProcessStructureStats[index], oIOSCoreDumpAnalysis.oIOSCoreDump)

def FilterInitBlocksForString(coredumpFilename, searchTerm):
    oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error != None:
        return []
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap == None:
        print('Heap region not found')
        return []
    oIOSMemoryParser = impf.cIOSMemoryParser(memoryHeap)
    oIOSMemoryParser.ResolveNames(oIOSCoreDump)
    found = []
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
        if oIOSMemoryBlockHeader.AllocNameResolved == 'Init':
            dStrings = uf.SearchASCIIStrings(oIOSMemoryBlockHeader.GetData())
            for value in dStrings.values():
                if value.find(searchTerm) >= 0:
                    found.append(value)
    return found

def IOSHistory(coredumpFilename, arguments=None):
    history = []
    for command in FilterInitBlocksForString(coredumpFilename, b'CMD: '):
        oMatch = re.search(b"'(.+)' (.+)", command)
        if oMatch:
            history.append((uf.ParseDateTime(oMatch.group(2).decode('utf-8')), oMatch.group(1).decode('utf-8')))
    for command in sorted(history, key=lambda x: x[0]):
        print(f"{command[0].strftime('%b %d %Y %H:%M:%S')} UTC: {command[1]}")
    if not history:
        print('No history found')

def IOSEvents(coredumpFilename, arguments=None):
    events = []
    for raw_event in FilterInitBlocksForString(coredumpFilename, b': %'):
        dtg = uf.ParseDateTime(raw_event.decode('utf-8'))
        data = raw_event[22:].decode('utf-8')
        events.append((dtg, data))
    for event in sorted(events, key=lambda x: x[0][0]):
        print(f"{event[0][0].strftime('%b %d %Y %H:%M:%S')}.{event[0][1]} UTC: {event[1]}")

def IOSCheckText(coredumpFilename, imageFilename, arguments):
    print("Comparing CW_SYSDESCR between core dump and IOS image")
    oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != None:
        print(oIOSCoreDump.error)
        return
    else:
        textAddress, textCoredump = oIOSCoreDump.RegionTEXT()
        if textCoredump == None:
            print('Error extracting text region from coredump {}'.format(coredumpFilename))
            return
        sysdescrCoredump = ''
        dataAddress, dataCoredump = oIOSCoreDump.RegionDATA()
        if dataCoredump != None:
            oCWStrings = impf.cCiscoCWStrings(dataCoredump)
            if oCWStrings.error == None and b'CW_SYSDESCR' in oCWStrings.dCWStrings:
                sysdescrCoredump = oCWStrings.dCWStrings[b'CW_SYSDESCR'].decode('utf-8')

    image = uf.File2Data(imageFilename)
    if image == None:
        print('Error reading image {}'.format(imageFilename))
        return

    oIOSImage = iipf.cIOSImage(image)
    if oIOSImage.error != 0:
        return
    sysdescrImage = ''
    if oIOSImage.oCWStrings != None and oIOSImage.oCWStrings.error == None and b'CW_SYSDESCR' in oIOSImage.oCWStrings.dCWStrings:
        sysdescrImage = oIOSImage.oCWStrings.dCWStrings[b'CW_SYSDESCR'].decode('utf-8')
    if sysdescrCoredump != '' or sysdescrImage != '':
        if sysdescrCoredump == sysdescrImage:
            print('CW_SYSDESCR are identical:\n')
            print(sysdescrCoredump)
        elif sysdescrCoredump == sysdescrImage.replace('-MZ', '-M', 1):
            print('CW_SYSDESCR are equivalent:\n')
            print(sysdescrCoredump)
        else:
            print('CW_SYSDESCR are different:\n')
            print(sysdescrCoredump)
            print('')
            print(sysdescrImage)
        print('')

    oELF = iipf.cELF(oIOSImage.imageUncompressed)
    if oELF.error != 0:
        print('ELF parsing error {:d}.'.format(oELF.error))
        return
    countSectionExecutableInstructions = 0
    countSectionSRELOC = 0
    for oSectionHeader in oELF.sections:
        if oSectionHeader.flags & 4: # SHF_EXECINSTR executable instructions
            textSectionData = oSectionHeader.sectionData
            countSectionExecutableInstructions += 1
        if oSectionHeader.nameIndexString == 'sreloc':
            countSectionSRELOC += 1
    if countSectionExecutableInstructions != 1:
        print('Error executable sections in image: found {:d} sections, expected 1'.format(countSectionExecutableInstructions))
        return
    if countSectionSRELOC != 0:
        print('Error found {:d} sreloc section in image: checktext command does not support relocation'.format(countSectionSRELOC))
        return
    start = textAddress & 0xFF # to be further researched
    textImage = textSectionData[start:start + len(textCoredump)]
    if len(textCoredump) != len(textImage):
        print('the text region is longer than the text section')
        print('len(textCoredump) = {:d}'.format(len(textCoredump)))
        print('len(textImage) = {:d}'.format(len(textImage)))
    countBytesDifferent = 0
    shortestLength = min(len(textCoredump), len(textImage))
    for iIter in range(shortestLength):
        if textCoredump[iIter] != textImage[iIter]:
            if countBytesDifferent == 0:
                print('text region and section are different starting 0x{:08X} in coredump (iter = 0x{:08X})'.format((textAddress + iIter), iIter))
            countBytesDifferent += 1
    if countBytesDifferent == 0:
        print('text region and section are identical')
    else:
        print('number of different bytes: {:d} ({:.2f}%)'.format(countBytesDifferent, (countBytesDifferent * 100.0) / shortestLength))

# http://phrack.org/issues/60/7.html
def IOSIntegrityText(coredumpFilename, arguments):
    oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != None:
        print(oIOSCoreDump.error)
        return
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap == None:
        print('Heap region not found')
        return
    oIOSMemoryParser = impf.cIOSMemoryParser(memoryHeap)
    print('Check start magic:')
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
        if oIOSMemoryBlockHeader.GetRawData()[0:4] != impf.cCiscoMagic.STR_BLOCK_BEGIN:
            print(oIOSMemoryBlockHeader.ShowLine())
            hit = True
    if not hit:
        print('OK')
    print('Check end magic:')
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
        if struct.unpack('>I', oIOSMemoryBlockHeader.GetRawData()[-4:])[0] != impf.cCiscoMagic.INT_BLOCK_CANARY and oIOSMemoryBlockHeader.RefCnt > 0:
            print(oIOSMemoryBlockHeader.ShowLine())
            hit = True
    if not hit:
        print('OK')
    print('Check previous block:')
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers[1:]:
        if oIOSMemoryBlockHeader.PrevBlock == 0:
            print(oIOSMemoryBlockHeader.ShowLine())
            hit = True
    if not hit:
        print('OK')
    print('Check next block:')
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers[:-1]:
        if oIOSMemoryBlockHeader.NextBlock == 0:
            print(oIOSMemoryBlockHeader.ShowLine())
            hit = True
    if not hit:
        print('OK')
