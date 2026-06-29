#!/usr/bin/env python3

__description__ = "Network Appliance Forensic Toolkit - IOS Core Dumps"
__version__ = "1.0.2"
__original_author__ = "Didier Stevens"
__current_authors__ = "@digitalsleuth and @G-K7"
__date__ = "2026/06/29"

import struct
import re
import os
from datetime import datetime
import naft.modules.uf as uf
import naft.modules.impf as impf
import naft.modules.pfef as pfef
import naft.modules.iipf as iipf


def IOSRegions(coredumpFilename, arguments):
    oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.err is not None:
        print(oIOSCoreDump.err)
    else:
        print("Start      End        Size       Name")
        for region in oIOSCoreDump.regions:
            if region[2] is not None:
                print(
                    f"0x{region[1]:08X} 0x{(region[1] + region[2] - 1):08X} {region[2]:<10d} {region[0]}"
                )
                if arguments["output"]:
                    uf.Data2File(
                        oIOSCoreDump.Region(region[0])[1],
                        f"{os.path.basename(coredumpFilename)}-{region[0]}-0x{region[1]:08X}",
                        arguments["output"],
                    )
            else:
                print(f'0x{region[1]:08X} {(" " * 21)} {region[0]}')
        addressBSS, dataBSS = oIOSCoreDump.RegionBSS()


def File2Strings(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [line.rstrip("\n") for line in f]
    except:
        return None


def ProcessAt(argument):
    if argument.startswith("@"):
        strings = File2Strings(argument[1:])
        if strings is None:
            raise Exception(f"Error reading {argument}")
        else:
            return strings
    return [argument]


def ProcessHeap(oIOSMemoryBlockHeader, arguments, coredumpFilename, output_path=None):
    if not arguments["strings"]:
        print(oIOSMemoryBlockHeader.ShowLine())
    if arguments["strings"]:
        dStrings = uf.SearchASCIIStrings(oIOSMemoryBlockHeader.GetData())
        if arguments["grep"] != "":
            printHeader = True
            for key, value in dStrings.items():
                if value.find(arguments["grep"].encode("utf-8")) >= 0:
                    if printHeader:
                        print(oIOSMemoryBlockHeader.ShowLine())
                        printHeader = False
                    print(
                        f' {(oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.BlockSize + key):08X}: {value.decode("utf-8")}'
                    )
        elif arguments["minimum"] == 0 or len(dStrings) >= arguments["minimum"]:
            print(oIOSMemoryBlockHeader.ShowLine())
            for key, value in dStrings.items():
                print(
                    f' {(oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.BlockSize + key):08X}: {value.decode("utf-8")}'
                )
    if arguments["dump"]:
        uf.DumpBytes(
            oIOSMemoryBlockHeader.GetData(),
            oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.headerSize,
        )
    if arguments["dumpraw"]:
        uf.DumpBytes(oIOSMemoryBlockHeader.GetRawData(), oIOSMemoryBlockHeader.address)
    if arguments["output"]:
        uf.Data2File(
            oIOSMemoryBlockHeader.GetData(),
            f"{coredumpFilename}-heap-0x{oIOSMemoryBlockHeader.address:08X}.data",
            output_path,
        )
        if arguments["verbose"]:
            print(
                f"\tFile: {output_path}{coredumpFilename}-heap-0x{oIOSMemoryBlockHeader.address:08X}.data created.\n"
            )


def IOSHeap(coredumpFilename, arguments):
    if arguments["output"] is not None:
        output_path = os.path.join(arguments["output"], "heap_data")
        os.mkdir(output_path)
    else:
        output_path = ""
    oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.err is not None:
        print(oIOSCoreDump.err)
        return
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap is None:
        print("Heap region not found")
        return
    oIOSMemoryParser = impf.cIOSMemoryParser(memoryHeap)
    if arguments["resolve"] or arguments["filter"] != "":
        oIOSMemoryParser.ResolveNames(oIOSCoreDump)
    if arguments["filter"] == "":
        print(impf.cIOSMemoryBlockHeader.ShowHeader)
        for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
            ProcessHeap(oIOSMemoryBlockHeader, arguments, coredumpFilename, output_path)
    else:
        print(impf.cIOSMemoryBlockHeader.ShowHeader)
        for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
            if oIOSMemoryBlockHeader.AllocNameResolved == arguments["filter"]:
                ProcessHeap(
                    oIOSMemoryBlockHeader, arguments, coredumpFilename, output_path
                )


def IOSCWStringsSub(data):
    oCWStrings = impf.cCiscoCWStrings(data)
    if oCWStrings.err is not None:
        print(oCWStrings.err)
        return
    keys = list(oCWStrings.dCWStrings.keys())
    keys.sort()
    for key in keys:
        if key == b"CW_SYSDESCR":
            print(f'{key.decode("utf-8")}:')
            print(oCWStrings.dCWStrings[key].decode("utf-8"))
        else:
            print(
                f'{key.decode("utf-8")}:{(' ' * (22 - len(key)))}{oCWStrings.dCWStrings[key].decode("utf-8")}'
            )


def IOSCWStrings(coredumpFilename, arguments):
    if arguments["raw"]:
        coredump = uf.File2Data(coredumpFilename)
        if coredump is None:
            print(f"Error reading file {coredumpFilename}")
        else:
            IOSCWStringsSub(coredump)
    else:
        oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
        if oIOSCoreDump.err is not None:
            print(oIOSCoreDump.err)
            return
        addressData, memoryData = oIOSCoreDump.RegionDATA()
        if memoryData is None:
            print("Data region not found")
            return
        IOSCWStringsSub(memoryData)


def PrintStatsAnalysis(dStats, oIOSCoreDump):
    keys1 = list(dStats.keys())
    keys1.sort()
    for key1 in keys1:
        countKeys = len(dStats[key1])
        keys2 = list(dStats[key1].keys())
        keys2.sort()
        if 2 < countKeys <= 7:
            bucket = "-> " + " ".join(
                [f"{key2:X}:{dStats[key1][key2]:d}" for key2 in keys2]
            )
        else:
            bucket = ""
        filtered = [x for x in dStats[key1] if x != 0]
        if filtered == []:
            filteredMin = min(dStats[key1])
        else:
            filteredMin = min(filtered)
        unfilteredMax = max(dStats[key1])
        regionNames = []
        for region in oIOSCoreDump.regions:
            if region[2] is not None:
                if (
                    region[1] <= filteredMin <= region[1] + region[2] - 1
                    or region[1] <= unfilteredMax <= region[1] + region[2] - 1
                ):
                    if region[0] not in regionNames:
                        regionNames.append(region[0])
        regionNames.sort()
        regionName = " ".join(regionNames).strip()
        print(
            f"{key1:3d} {(key1*4):3X}: {countKeys:3d} {min(dStats[key1]):08X} {filteredMin:08X} {unfilteredMax:08X} {regionName} {bucket}"
        )


def IOSProcesses(coredumpFilename, arguments):
    oIOSCoreDumpAnalysis = impf.cIOSCoreDumpAnalysis(coredumpFilename)
    if oIOSCoreDumpAnalysis.err is not None:
        print(oIOSCoreDumpAnalysis.err)
        return
    print(
        f"{'PID':>4} "
        f"{'QTy':>3} "
        f"{'PC':<8} "
        f"{'Runtime (ms)':>12} "
        f"{'Invoked':>10} "
        f"{'uSecs':>8} "
        f"{'Stacks':>12} "
        f"{'TTY':>4} "
        f"{'StackBlk':>8} "
        f"Process"
    )
    for processID, addressProcess, oIOSProcess in oIOSCoreDumpAnalysis.processes:
        if arguments["filter"] == "" or processID == int(arguments["filter"]):
            if oIOSProcess is not None:
                if oIOSProcess.err == "":
                    line = oIOSProcess.Line()
                else:
                    line = f"{processID:4d} {oIOSProcess.err}"
                print(line)
                if arguments["dump"]:
                    uf.DumpBytes(oIOSProcess.data, addressProcess)
            else:
                print(
                    f" {processID:>3d} {addressProcess:08X} - addressProcess not found"
                )
    if oIOSCoreDumpAnalysis.RanHeuristics:
        print("")
        print("*** WARNING ***")
        print("Unexpected process structure")
        print("Please reports these results")
        print("Fields determined with heuristics:")
        print(f"Process structure size: {oIOSCoreDumpAnalysis.HeuristicsSize:d}")
        keys = list(oIOSCoreDumpAnalysis.HeuristicsFields.keys())
        keys.sort(key=str.lower)
        for key in keys:
            value = oIOSCoreDumpAnalysis.HeuristicsFields[key]
            if value is not None:
                print(f"{key:-22s}: 0x{value[1]:04X}")
    if arguments["stats"]:
        keys = list(oIOSCoreDumpAnalysis.dProcessStructureStats.keys())
        keys.sort()
        print(f"Number of different process structures: {len(keys):d}")
        for index in keys:
            print(f"Process structures length: {index:d}")
            PrintStatsAnalysis(
                oIOSCoreDumpAnalysis.dProcessStructureStats[index],
                oIOSCoreDumpAnalysis.oIOSCoreDump,
            )


def FilterInitBlocksForString(coredumpFilename, searchTerm):
    oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.err is not None:
        return []
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap is None:
        print("Heap region not found")
        return []
    oIOSMemoryParser = impf.cIOSMemoryParser(memoryHeap)
    oIOSMemoryParser.ResolveNames(oIOSCoreDump)
    found = []
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
        if oIOSMemoryBlockHeader.AllocNameResolved == "Init":
            dStrings = uf.SearchASCIIStrings(oIOSMemoryBlockHeader.GetData())
            for value in dStrings.values():
                if value.find(searchTerm) >= 0:
                    found.append(value)
    return found


def IOSHistory(coredumpFilename, arguments=None):
    history = []
    hist_time_format = "%b %d %Y %H:%M:%S.%f %Z"
    CMD_PATTERN = re.compile(
        rb"CMD: '(.+?)' " rb"(\d{2}:\d{2}:\d{2} \S+ \S+ \S+ \d{1,2} \d{4})"
    )
    for command in FilterInitBlocksForString(coredumpFilename, b"CMD: "):
        oMatch = CMD_PATTERN.search(command)
        if oMatch:
            timestamp = oMatch.group(2).decode("utf-8")
            dt = uf.ParseDateTime(timestamp)
            history.append((dt, oMatch.group(1).decode("utf-8")))
    if not history:
        print("No history found")
        return
    for command in sorted(history, key=lambda x: x[0]):
        formatted_time = command[0].strftime(hist_time_format)
        print(f"{formatted_time}: {command[1]}")


def IOSEvents(coredumpFilename, arguments=None):
    events = []
    evt_time_format = "%b %d %Y %H:%M:%S.%f"
    EVT_PATTERN = re.compile(
        rb"([\w\s\d:]+\.\d{3,6})(.*)"
    )
    for raw_event in FilterInitBlocksForString(coredumpFilename, b": %"):
        decoded_event = raw_event.decode("utf-8")
        clean_event, cmd_string, _ = decoded_event.partition("CMD:")
        oMatch = EVT_PATTERN.search(clean_event.encode("utf-8"))
        if oMatch:
            timestamp_str = oMatch.group(1).decode("utf-8").strip()
            event_data = oMatch.group(2).decode("utf-8").strip(" :").rstrip()
            dt_object = uf.ParseDateTime(timestamp_str, time_format=None)
            events.append((dt_object, event_data))
    if not events:
        print("No events found")
        return
    for event in sorted(events, key=lambda x: x[0]):
        formatted_time = event[0].strftime(evt_time_format)
        print(f"{formatted_time}: {event[1]}")


def IOSCheckText(coredumpFilename, imageFilename, arguments):
    print("Comparing CW_SYSDESCR between core dump and IOS image")
    oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.err is not None:
        print(oIOSCoreDump.err)
        return
    textAddress, textCoredump = oIOSCoreDump.RegionTEXT()
    if textCoredump is None:
        print(f"Error extracting text region from coredump {coredumpFilename}")
        return
    sysdescrCoredump = ""
    dataAddress, dataCoredump = oIOSCoreDump.RegionDATA()
    if dataCoredump is not None:
        oCWStrings = impf.cCiscoCWStrings(dataCoredump)
        if oCWStrings.err is None and b"CW_SYSDESCR" in oCWStrings.dCWStrings:
            sysdescrCoredump = oCWStrings.dCWStrings[b"CW_SYSDESCR"].decode("utf-8")
    image = uf.File2Data(imageFilename)
    if image is None:
        print(f"Error reading image {imageFilename}")
        return
    oIOSImage = iipf.cIOSImage(image, imageFilename)
    if oIOSImage.err != 0:
        return
    sysdescrImage = ""
    if (
        oIOSImage.oCWStrings is not None
        and oIOSImage.oCWStrings.err is None
        and b"CW_SYSDESCR" in oIOSImage.oCWStrings.dCWStrings
    ):
        sysdescrImage = oIOSImage.oCWStrings.dCWStrings[b"CW_SYSDESCR"].decode("utf-8")
    if sysdescrCoredump != "" or sysdescrImage != "":
        if sysdescrCoredump == sysdescrImage:
            print("CW_SYSDESCR are identical:\n")
            print(sysdescrCoredump)
        elif sysdescrCoredump == sysdescrImage.replace("-MZ", "-M", 1):
            print("CW_SYSDESCR are equivalent:\n")
            print(sysdescrCoredump)
        else:
            print("CW_SYSDESCR are different:\n")
            print(sysdescrCoredump)
            print("")
            print(sysdescrImage)
        print("")
    oELF = iipf.cELF(oIOSImage.imageUncompressed)
    if oELF.err != 0:
        print(f"ELF parsing error {oELF.err:d}.")
        return
    countSectionExecutableInstructions = 0
    countSectionSRELOC = 0
    for oSectionHeader in oELF.sections:
        if oSectionHeader.flags & 4:  # SHF_EXECINSTR executable instructions
            textSectionData = oSectionHeader.sectionData
            countSectionExecutableInstructions += 1
        if oSectionHeader.nameIndexString == "sreloc":
            countSectionSRELOC += 1
    if countSectionExecutableInstructions != 1:
        print(
            f"Error executable sections in image: found {countSectionExecutableInstructions:d} sections, expected 1"
        )
        return
    if countSectionSRELOC != 0:
        print(
            f"Error found {countSectionSRELOC:d} sreloc section in image: checktext command does not support relocation"
        )
        return
    start = textAddress & 0xFF  # to be further researched
    textImage = textSectionData[start : start + len(textCoredump)]
    if len(textCoredump) != len(textImage):
        print("the text region is longer than the text section")
        print(f"len(textCoredump) = {len(textCoredump):d}")
        print(f"len(textImage) = {len(textImage):d}")
    countBytesDifferent = 0
    shortestLength = min(len(textCoredump), len(textImage))
    for iIter in range(shortestLength):
        if textCoredump[iIter] != textImage[iIter]:
            if countBytesDifferent == 0:
                print(
                    f"text region and section are different starting 0x{(textAddress + iIter):08X} in coredump (iter = 0x{iIter:08X})"
                )
            countBytesDifferent += 1
    if countBytesDifferent == 0:
        print("text region and section are identical")
    else:
        print(
            f"number of different bytes: {countBytesDifferent:d} ({((countBytesDifferent * 100.0) / shortestLength):.2f}%)"
        )


def IOSIntegrityText(coredumpFilename, arguments):
    oIOSCoreDump = impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.err is not None:
        print(oIOSCoreDump.err)
        return
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap is None:
        print("Heap region not found")
        return
    oIOSMemoryParser = impf.cIOSMemoryParser(memoryHeap)
    print("Check start magic:")
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
        if oIOSMemoryBlockHeader.GetRawData()[0:4] != impf.cCiscoMagic.STR_BLOCK_BEGIN:
            print(oIOSMemoryBlockHeader.ShowLine())
            hit = True
    if not hit:
        print("OK")
    print("Check end magic:")
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
        if (
            struct.unpack(">I", oIOSMemoryBlockHeader.GetRawData()[-4:])[0]
            != impf.cCiscoMagic.INT_BLOCK_CANARY
            and oIOSMemoryBlockHeader.RefCnt > 0
        ):
            print(oIOSMemoryBlockHeader.ShowLine())
            hit = True
    if not hit:
        print("OK")
    print("Check previous block:")
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers[1:]:
        if oIOSMemoryBlockHeader.PrevBlock == 0:
            print(oIOSMemoryBlockHeader.ShowLine())
            hit = True
    if not hit:
        print("OK")
    print("Check next block:")
    hit = False
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers[:-1]:
        if oIOSMemoryBlockHeader.NextBlock == 0:
            print(oIOSMemoryBlockHeader.ShowLine())
            hit = True
    if not hit:
        print("OK")
