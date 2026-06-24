#!/usr/bin/env python3

__description__ = "Network Appliance Forensic Toolkit - IOS Memory Parsing Functions"
__version__ = "1.0.1"
__original_author__ = "Didier Stevens"
__current_authors__ = "@digitalsleuth and @G-K7"
__date__ = "2026/06/15"

import struct
import re
import naft.modules.uf as uf


class cCiscoMagic:
    STR_REGIONS = b"\xde\xad\x12\x34"
    INT_BLOCK_BEGIN = 0xAB1234CD
    STR_BLOCK_BEGIN = b"\xab\x12\x34\xcd"
    INT_BLOCK_CANARY = 0xFD0110DF
    INT_BLOCK_FREE = 0xDEADBEEF
    STR_PROCESS_END = b"\xbe\xef\xca\xfe"

    STR_FEEDFACE = b"\xfe\xed\xfa\xce"
    STR_FADEFAD1 = b"\xfa\xde\xfa\xd1\x00\x00\x00\x18"
    STR_BAD00B1E = b"\xba\xd0\x0b\x1e"

    STR_CW_DELIMITER = b"$"
    STR_CW_ = b"CW_"
    STR_CW_BEGIN = STR_CW_ + b"BEGIN" + STR_CW_DELIMITER
    STR_CW_END = STR_CW_ + b"END" + STR_CW_DELIMITER


class cIOSCoreDump:

    def __init__(self, coredumpFilename):
        self.coredumpFilename = coredumpFilename
        self.Parse()

    def Parse(self):
        self.err = None
        self.coredump = uf.File2Data(self.coredumpFilename)
        if self.coredump is None:
            self.err = f"Error reading coredump {self.coredumpFilename}"
            return
        indexRegionsMetaData = self.coredump.find(cCiscoMagic.STR_REGIONS)
        if indexRegionsMetaData < 0:
            self.err = (
                f"Magic sequence {cCiscoMagic.STR_REGIONS.hex().upper()} not found"
            )
            return
        if (
            self.coredump[indexRegionsMetaData + 4 : indexRegionsMetaData + 4 + 4]
            != b"\x00\x00\x00\x05"
        ):
            self.err = f"Unexpected data found: {self.coredump[indexRegionsMetaData + 4:indexRegionsMetaData + 4 + 4].hex()}"
            return
        addresses = struct.unpack(
            ">IIII",
            self.coredump[
                indexRegionsMetaData + 20 : indexRegionsMetaData + 20 + 4 * 4
            ],
        )
        indexHeap = self.coredump.find(
            cCiscoMagic.STR_BLOCK_BEGIN, addresses[3] - addresses[0]
        )
        if indexHeap < 0:
            self.err = (
                f"Magic sequence {cCiscoMagic.STR_BLOCK_BEGIN.hex().upper()} not found"
            )
            return
        self.address = addresses[0]
        self.size = len(self.coredump)
        addressBegin = self.address
        addressEnd = self.address + self.size
        regionsCalculation = list(zip(("begin", "text", "data", "bss"), addresses))
        regionsCalculation.append(("heap", addresses[0] + indexHeap))
        regionsCalculation.append(("end", addressEnd))
        indices = list(range(len(regionsCalculation)))
        for index, value in enumerate(indices):
            address = regionsCalculation[value][1]
            if address < addressBegin or address > addressEnd:
                del indices[index]
            regionsCalculation[value] = (
                regionsCalculation[value][0],
                regionsCalculation[value][1],
                None,
                None,
            )
        for index, value in enumerate(indices[:-1]):
            length = (
                regionsCalculation[indices[index + 1]][1] - regionsCalculation[value][1]
            )
            regionsCalculation[value] = (
                regionsCalculation[value][0],
                regionsCalculation[value][1],
                length,
                regionsCalculation[value][1] - addressBegin,
            )
        self.regions = regionsCalculation[:-1]

    def Region(self, name):
        for region in self.regions:
            if region[0].lower() == name.lower():
                if region[2] is None:
                    return region[1], None
                return region[1], self.coredump[region[3] : region[3] + region[2]]
        return None, None

    def RegionTEXT(self):
        return self.Region("text")

    def RegionDATA(self):
        return self.Region("data")

    def RegionBSS(self):
        return self.Region("bss")

    def RegionHEAP(self):
        return self.Region("heap")

    def GetString(self, address):
        index = address - self.address
        if index < 0 or index >= self.size:
            return None
        string = ""
        iterant = 0
        while (
            index + iterant < self.size
            and self.coredump[index + iterant] != 0
            and iterant < 50
        ):
            string += chr(self.coredump[(index + iterant)])
            iterant += 1
        return string

    def GetInteger32(self, address):
        index = address - self.address
        if index < 0 or index - 4 >= self.size:
            return None
        return struct.unpack(">I", self.coredump[index : index + 4])[0]


class cIOSMemoryBlockHeader:

    def __init__(self, data, headerSize, index, baseAddress, oIOSMemoryParser):
        self.data = data
        self.err = 0
        self.headerSize = headerSize
        if len(data) != 0:
            if headerSize == 40:
                header = struct.unpack(">IIIIIIIIII", data[0:headerSize])
            elif headerSize == 48:
                header = struct.unpack(">IIIIIIIIIIII", data[0:headerSize])
            else:
                self.err = 1
                return
            if header[0] != cCiscoMagic.INT_BLOCK_BEGIN:
                self.err = 2
                return
            self.index = index
            self.address = index + baseAddress
            self.addressData = self.address + headerSize
            self.oIOSMemoryParser = oIOSMemoryParser
            self.PID = header[1]
            self.AllocCheck = header[2]
            self.AllocName = header[3]
            self.AllocNameResolved = ""
            self.AllocPC = header[4]
            self.NextBlock = header[5]
            self.PrevBlock = header[6] - 0x14
            if self.PrevBlock < baseAddress:
                self.PrevBlock = 0
            self.BlockFree, self.BlockSize = self.ParseSizeField(header[7])
            self.RefCnt = header[8]
            self.LastFree = header[9]
            self.NextFree = None
            self.PrevFree = None
            if self.BlockFree:
                freeHeader = struct.unpack(
                    ">IIIIII", data[headerSize : headerSize + 24]
                )
                if freeHeader[0] != cCiscoMagic.INT_BLOCK_FREE:
                    self.err = 3
                    return
                if freeHeader[4] >= baseAddress:
                    self.NextFree = freeHeader[4] - self.headerSize
                else:
                    self.NextFree = 0
                if freeHeader[5] >= baseAddress:
                    self.PrevFree = freeHeader[5] - self.headerSize - 0x10
                else:
                    self.PrevFree = 0
        else:
            self.err = 4
            return

    def ParseSizeField(self, value):
        free = value & 0x80000000 == 0x00000000
        size = (value & 0x7FFFFFFF) * 2
        return free, size

    def GetData(self):
        start = self.index + self.headerSize
        if (
            struct.unpack(
                ">I",
                self.oIOSMemoryParser.memory[
                    start + self.BlockSize - 4 : start + self.BlockSize
                ],
            )[0]
            == cCiscoMagic.INT_BLOCK_CANARY
        ):
            return self.oIOSMemoryParser.memory[start : start + self.BlockSize - 4]
        return self.oIOSMemoryParser.memory[start : start + self.BlockSize]

    def GetRawData(self):
        return self.oIOSMemoryParser.memory[
            self.index : self.index + self.headerSize + self.BlockSize
        ]

    def ShowLine(self):
        if self.AllocNameResolved == "" or self.AllocNameResolved is None:
            allocName = f"{self.AllocName:08X}"
        else:
            allocName = self.AllocNameResolved
        if self.NextFree is None:
            NextFree = "--------"
        else:
            NextFree = f"{f'{self.NextFree:X}':->8s}"
        if self.PrevFree is None:
            PrevFree = "--------"
        else:
            PrevFree = f"{f'{self.PrevFree:X}':->8s}"
        return f"{self.address:08X} {self.BlockSize:010d} {self.PrevBlock:08X} {self.NextBlock:08X} {self.RefCnt:03d} {PrevFree} {NextFree} {self.AllocPC:08X} {allocName}"

    ShowHeader = (
        "Address\t Bytes\t    PrevBlk  NextBlk  Ref PrevFree NextFree AllocPC  What"
    )


class cIOSMemoryParser:

    def __init__(self, memory):
        self.memory = memory
        self.length = len(memory)
        self.headerSize = 40
        self.baseAddress = None
        self.Headers = []
        self.dNames = {}
        self.dHeadersAddressData = {}
        self.dResolvedNames = {}
        self.Parse()

    def ParseSizeField(self, value):
        free = value & 0x80000000 == 0x80000000
        size = (value & 0x7FFFFFFF) * 2
        return free, size

    def InitialChecks(self):
        if self.length < self.headerSize:
            return False
        header = struct.unpack(">IIIIIIIIII", self.memory[0 : self.headerSize])
        if header[0] != cCiscoMagic.INT_BLOCK_BEGIN:
            return False
        free, size = self.ParseSizeField(header[7])
        if self.length < self.headerSize + size + self.headerSize:
            return False
        header = struct.unpack(
            ">IIIIIIIIII",
            self.memory[
                self.headerSize + size : self.headerSize + size + self.headerSize
            ],
        )
        if header[0] != cCiscoMagic.INT_BLOCK_BEGIN:
            self.headerSize = 48
            if self.length < self.headerSize + size + self.headerSize:
                return False
            header = struct.unpack(
                ">IIIIIIIIIIII",
                self.memory[
                    self.headerSize + size : self.headerSize + size + self.headerSize
                ],
            )
            if header[0] != cCiscoMagic.INT_BLOCK_BEGIN:
                return False
        self.baseAddress = header[6] - 0x14
        return True

    def ExtractHeaders(self):
        index = 0
        while True:
            oIOSMemoryBlockHeader = cIOSMemoryBlockHeader(
                self.memory[index : index + self.headerSize + 24],
                self.headerSize,
                index,
                self.baseAddress,
                self,
            )
            if oIOSMemoryBlockHeader.err != 0:
                if oIOSMemoryBlockHeader.err == 4:
                    return False
                print(f"Error {oIOSMemoryBlockHeader.err:d}")
                return False
            self.Headers.append(oIOSMemoryBlockHeader)
            self.dHeadersAddressData[oIOSMemoryBlockHeader.addressData] = (
                oIOSMemoryBlockHeader
            )
            if oIOSMemoryBlockHeader.NextBlock == 0:
                return True
            if oIOSMemoryBlockHeader.AllocName in self.dNames:
                self.dNames[oIOSMemoryBlockHeader.AllocName] += 1
            else:
                self.dNames[oIOSMemoryBlockHeader.AllocName] = 1
            index = oIOSMemoryBlockHeader.NextBlock - self.baseAddress

    def Parse(self):
        if not self.InitialChecks():
            return False
        self.ExtractHeaders()
        return True

    def Show(self):
        print(cIOSMemoryBlockHeader.ShowHeader)
        for oIOSMemoryBlockHeader in self.Headers:
            print(oIOSMemoryBlockHeader.ShowLine())

    def ResolveNames(self, oIOSCoreDump):
        for address in self.dNames:
            self.dResolvedNames[address] = oIOSCoreDump.GetString(address)
        for oIOSMemoryBlockHeader in self.Headers:
            if oIOSMemoryBlockHeader.AllocName in self.dResolvedNames:
                oIOSMemoryBlockHeader.AllocNameResolved = self.dResolvedNames[
                    oIOSMemoryBlockHeader.AllocName
                ]


class cCiscoCWStrings:

    def __init__(self, data):
        self.data = data
        self.err = None
        self.dCWStrings = {}
        begin = uf.FindAllStrings(self.data, cCiscoMagic.STR_CW_BEGIN)
        if len(begin) == 0:
            self.err = "Error: CW_BEGIN not found"
            return
        if len(begin) > 1:
            self.err = "Error: CW_BEGIN found multiple times"
            return
        end = uf.FindAllStrings(self.data, cCiscoMagic.STR_CW_END)
        if len(end) == 0:
            self.err = "Error: CW_END not found"
            return
        if len(end) > 1:
            self.err = "Error: CW_END found multiple times"
            return
        if begin[0] >= end[0]:
            self.err = "Error: CW_BEGIN not before CW_END"
            return
        finalDelimiter = self.data.find(
            cCiscoMagic.STR_CW_DELIMITER, end[0] + len(cCiscoMagic.STR_CW_END)
        )
        if finalDelimiter < 0:
            self.err = "Error: final delimiter $ not found"
            return
        cwStrings = self.data[begin[0] : finalDelimiter + 1]
        for index in uf.FindAllStrings(cwStrings, cCiscoMagic.STR_CW_):
            startCWString = cwStrings[index:]
            delimiters = uf.FindAllStrings(startCWString, cCiscoMagic.STR_CW_DELIMITER)
            if len(delimiters) < 2:
                self.err = "Error: delimiters $ not found"
                return
            self.dCWStrings[startCWString[0 : delimiters[0]]] = startCWString[
                delimiters[0] + 1 : delimiters[1]
            ]


class cIOSProcess:

    dFields = {
        664: {
            "addressProcessName": (">I", 0xC8),
            "PC": (">I", 0x70),
            "Q": (">I", 0xCC),
            "Ty": (">I", 0x64),
            "Runtime": (">I", 0x9C),
            "Invoked": (">I", 0x250),
            "Stack1": (">I", 0x84),
            "Stack2": (">I", 0x80),
            "addressStackBlock": (">I", 0x00),
            "addressTTY": (">I", 0xF0),
        },
        692: {
            "addressProcessName": (">I", 0xD0),
            "PC": (">I", 0x6C),
            "Q": (">I", 0xD4),
            "Ty": (">I", 0x64),
            "Runtime": (">I", 0xB8),
            "Invoked": (">I", 0xC8),
            "Stack1": (">I", 0xEC),
            "Stack2": (">I", 0xF0),
            "addressStackBlock": (">I", 0x00),
            "addressTTY": (">I", 0xF8),
        },
        696: {
            "addressProcessName": (">I", 0xE8),
            "PC": (">I", 0x90),
            "Q": (">I", 0xEC),
            "Ty": (">I", 0x88),
            "Runtime": (">I", 0xD8),
            "Invoked": (">I", 0xE0),
            "Stack1": (">I", 0x100),
            "Stack2": (">I", 0x104),
            "addressStackBlock": (">I", 0x00),
            "addressTTY": (">I", 0xC4),
        },
        712: {
            "addressProcessName": (">I", 0xE8),
            "PC": (">I", 0x90),
            "Q": (">I", 0xEC),
            "Ty": (">I", 0x88),
            "Runtime": (">I", 0xD0),
            "Invoked": (">I", 0xE0),
            "Stack1": (">I", 0x100),
            "Stack2": (">I", 0x104),
            "addressStackBlock": (">I", 0x00),
            "addressTTY": (">I", 0xC4),
        },
        732: {
            "addressProcessName": (">I", 0xF8),
            "PC": (">I", 0x90),
            "Q": (">I", 0xFC),
            "Ty": (">I", 0x88),
            "Runtime": (">I", 0xE0),
            "Invoked": (">I", 0xF0),
            "Stack1": (">I", 0x114),
            "Stack2": (">I", 0x118),
            "addressStackBlock": (">I", 0x00),
            "addressTTY": (">I", 0xCC),
        },
        744: {
            "addressProcessName": (">I", 0xD8),
            "PC": (">I", 0x70),
            "Q": (">I", 0xDC),
            "Ty": (">I", 0x68),
            "Runtime": (">I", 0xC0),
            "Invoked": (">I", 0xD0),
            "Stack1": (">I", 0xF8),
            "Stack2": (">I", 0xFC),
            "addressStackBlock": (">I", 0x00),
            "addressTTY": (">I", 0x100),
        },
    }

    def __init__(
        self,
        processID,
        data,
        oIOSCoreDump=None,
        dProcessStructureStats=None,
        dHeuristicsFields=None,
    ):
        if dHeuristicsFields is None:
            dHeuristicsFields = {}
        if dProcessStructureStats is None:
            dProcessStructureStats = {}
        if dHeuristicsFields != {}:
            for key, value in dHeuristicsFields.items():
                self.dFields[key] = value
        self.err = ""
        self.processID = processID
        self.data = data
        self.indexProcessEnd = self.data.find(
            cCiscoMagic.STR_PROCESS_END, 600, len(data)
        )  # BEEFCAFE can appear early in the process as well, parse for one near end of known range
        if self.indexProcessEnd < 0:
            self.err = "Error: parsing process structure, BEEFCAFE not found"
            return
        if not self.IsSupportedProcessStructure():
            self.addressProcessName = None
            self.err = f"Error: unexpected process structure, length = {self.indexProcessEnd:d}"
        else:
            self.SetFields()
            if self.Q is None:
                self.Q_str = "?"
            else:
                self.Q_str = cIOSProcess.Q2Str(self.Q)
            if self.Ty is None:
                self.Ty_str = "?"
            else:
                self.Ty_str = cIOSProcess.Ty2Str(self.Ty)
            addressIter = self.addressStackBlock
            if self.Stack2 is not None:
                while (
                    oIOSCoreDump.GetInteger32(addressIter) == 0xFFFFFFFF
                    and addressIter - self.addressStackBlock <= self.Stack2
                ):
                    addressIter += 4
            self.LowWaterMark = addressIter - self.addressStackBlock
            if self.addressTTY is None:
                self.TTY = None
            elif self.addressTTY == 0:
                self.TTY = 0
            elif oIOSCoreDump is None:
                self.TTY = None
            else:
                self.TTY = oIOSCoreDump.GetInteger32(self.addressTTY + 4)
        if self.indexProcessEnd not in dProcessStructureStats:
            dProcessStructureStats[self.indexProcessEnd] = {}
        self.CalcProcessStructureStats(dProcessStructureStats[self.indexProcessEnd])
        if oIOSCoreDump is None or self.addressProcessName is None:
            self.name = None
        else:
            self.name = oIOSCoreDump.GetString(self.addressProcessName)

    def IsSupportedProcessStructure(self):
        return self.indexProcessEnd in cIOSProcess.dFields

    def SetField(self, fieldName):
        if self.dFields[self.indexProcessEnd][fieldName] is None:
            exec(f"self.{fieldName} = None")
        else:
            fmt, position = self.dFields[self.indexProcessEnd][fieldName]
            fieldValue = struct.unpack(fmt, self.data[position : position + 4])[0]
            exec(f"self.{fieldName} = fieldValue")

    def SetFields(self):
        for fieldName in self.dFields[self.indexProcessEnd]:
            self.SetField(fieldName)

    @classmethod
    def Q2Str(cls, number):
        dPriorities = {2: "C", 3: "H", 4: "M", 5: "L"}
        # dPriorities = {1:'C', 2:'H', 3:'M', 4:'L'} #a# regression test this 12.4(25d) is 1, 2, 3, 4 - add priorities to fields?
        if number in dPriorities:
            return dPriorities[number]
        return str(number)

    @classmethod
    def Ty2Str(cls, number):
        dTys = {
            0: "*",
            1: "E",
            2: "S",
            3: "rd",
            4: "we",
            5: "sa",
            6: "si",
            7: "sp",
            8: "st",
            9: "hg",
            10: "xx",
        }  # untested
        if number in dTys:
            return dTys[number]
        return str(number)

    def CalcProcessStructureStats(self, dStats):
        for index, integer32 in enumerate(
            struct.unpack(">" + "I" * int(len(self.data) / 4), self.data)
        ):
            if index in dStats:
                bucket = dStats[index]
                if integer32 in bucket:
                    bucket[integer32] += 1
                else:
                    bucket[integer32] = 1
            else:
                dStats[index] = {integer32: 1}

    def Line(self):
        line = f"{self.processID:4d} {self.Q_str}{self.Ty_str:<2} "
        line += f"{self.PC:08X} " if self.PC is not None else f"{'?':>8} "
        line += f"{self.Runtime:12d} " if self.Runtime is not None else f"{'?':>12} "
        line += f"{self.Invoked:10d} " if self.Invoked is not None else f"{'?':>10} "
        if self.Invoked in (0, None) or self.Runtime is None:
            line += f"{'?':>8} "
        else:
            line += f"{int(self.Runtime * 1000 / self.Invoked):8d} "
        lwm = self.LowWaterMark if self.LowWaterMark is not None else '?'
        stk = self.Stack2 if self.Stack2 is not None else '?'
        stks = f"{lwm}/{stk}"
        line += f"{stks:>12}"
        line += f"{self.TTY:>5} " if self.TTY is not None else f"{'?':>5} "
        line += f"{self.addressStackBlock:08X} " if self.addressStackBlock is not None else f"{'?':>8} "
        line += uf.cn(self.name)
        return line


class cIOSCoreDumpAnalysis:

    def __init__(self, coredumpFilename):
        self.err = None
        self.RanHeuristics = False
        self.oIOSCoreDump = cIOSCoreDump(coredumpFilename)
        if self.oIOSCoreDump.err is not None:
            self.err = self.oIOSCoreDump.err
            return
        addressHeap, memoryHeap = self.oIOSCoreDump.RegionHEAP()
        if memoryHeap is None:
            self.err = "Heap region not found"
            return
        oIOSMemoryParser = cIOSMemoryParser(memoryHeap)
        oIOSMemoryParser.ResolveNames(self.oIOSCoreDump)
        dProcessArray = {}
        oLastProcessArray = None
        for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
            if oIOSMemoryBlockHeader.AllocNameResolved == "Process Array":
                processArray = oIOSMemoryBlockHeader.GetData()
                addressNextProcessArray = struct.unpack(">I", processArray[0:4])[0]
                if addressNextProcessArray == 0:
                    oLastProcessArray = oIOSMemoryBlockHeader
                else:
                    dProcessArray[addressNextProcessArray] = oIOSMemoryBlockHeader
        oIterProcessArray = oLastProcessArray
        addressProcesses = []
        while oIterProcessArray is not None:
            processArray = oIterProcessArray.GetData()
            countProcessesInThisArray = struct.unpack(">I", processArray[4:8])[0]
            addressProcessesInThisArray = []
            for addressProcess in struct.unpack(
                ">" + "I" * int(len(processArray[8:]) / 4), processArray[8:]
            ):
                if countProcessesInThisArray > 0:
                    addressProcessesInThisArray.append(addressProcess)
                    if addressProcess != 0:
                        countProcessesInThisArray -= 1
            addressProcessesInThisArray.extend(addressProcesses)
            addressProcesses = addressProcessesInThisArray
            addressProcessArray = oIterProcessArray.addressData
            if addressProcessArray in dProcessArray:
                oIterProcessArray = dProcessArray.get(addressProcessArray)
            else:
                oIterProcessArray = None
        self.processes = []
        self.dProcessStructureStats = {}
        countProcessStructureErrors = 0
        for index, addressProcess in enumerate(addressProcesses):
            if addressProcess != 0:
                if addressProcess in oIOSMemoryParser.dHeadersAddressData:
                    oIOSProcess = cIOSProcess(
                        index + 1,
                        oIOSMemoryParser.dHeadersAddressData[addressProcess].GetData(),
                        self.oIOSCoreDump,
                        self.dProcessStructureStats,
                    )
                    if oIOSProcess.err.startswith(
                        "Error: unexpected process structure, length ="
                    ):
                        countProcessStructureErrors += 1
                    self.processes.append((index + 1, addressProcess, oIOSProcess))
                else:
                    self.processes.append((index + 1, addressProcess, None))
        if float(countProcessStructureErrors) / float(len(self.processes)) >= 0.95:
            self.Heuristics()
            self.processes = []
            for index, addressProcess in enumerate(addressProcesses):
                if addressProcess != 0:
                    if addressProcess in oIOSMemoryParser.dHeadersAddressData:
                        oIOSProcess = cIOSProcess(
                            index + 1,
                            oIOSMemoryParser.dHeadersAddressData[
                                addressProcess
                            ].GetData(),
                            self.oIOSCoreDump,
                            self.dProcessStructureStats,
                            {self.HeuristicsSize: self.HeuristicsFields},
                        )
                        self.processes.append((index + 1, addressProcess, oIOSProcess))
                    else:
                        self.processes.append((index + 1, addressProcess, None))

    def HeuristicsStructureAnalysis(self):
        dStats = self.dProcessStructureStats[self.HeuristicsSize]
        self.dHeuristicsAnalysis = {}
        for key1 in dStats:
            countKeys = len(dStats[key1])
            filtered = [x for x in dStats[key1] if x != 0]
            if filtered == []:
                filteredMin = min(dStats[key1])
            else:
                filteredMin = min(filtered)
            unfilteredMax = max(dStats[key1])
            regionNames = []
            for region in self.oIOSCoreDump.regions:
                if region[2] is not None:
                    if (
                        region[1] <= filteredMin <= region[1] + region[2] - 1
                        or region[1] <= unfilteredMax <= region[1] + region[2] - 1
                    ):
                        if region[0] not in regionNames:
                            regionNames.append(region[0])
            regionNames.sort()
            self.dHeuristicsAnalysis[key1] = (
                countKeys,
                min(dStats[key1]),
                filteredMin,
                unfilteredMax,
                regionNames,
                dStats[key1],
            )

    def HeuristicsFindProcessName(self):
        valid = (
            (key, data[0])
            for key, data in self.dHeuristicsAnalysis.items()
            if key > 1 and data[1] != 0 and data[0] > 0 and "data" in data[4]
        )
        keyMax = max(valid, key=lambda x: x[1], default=None)
        if keyMax is not None:
            self.HeuristicsFields["addressProcessName"] = (">I", keyMax[0] * 4)

    def HeuristicsFindQ(self):
        matches = [
            key
            for key, data in self.dHeuristicsAnalysis.items()
            if data[0] > 1 and data[1] >= 2 and data[3] <= 5
        ]
        if len(matches) == 1:
            self.HeuristicsFields["Q"] = (">I", matches[0] * 4)

    def HeuristicsFindTy(self):
        matches = [
            key
            for key, data in self.dHeuristicsAnalysis.items()
            if data[0] > 1 and data[1] == 0 and data[5][0] <= 2 and 4 <= data[3] <= 10
        ]
        if len(matches) == 1:
            self.HeuristicsFields["Ty"] = (">I", matches[0] * 4)

    def HeuristicsAddMissingFields(self):
        defaults = {
            "addressProcessName": None,
            "PC": None,
            "Q": None,
            "Ty": None,
            "Runtime": None,
            "Invoked": None,
            "Stack1": None,
            "Stack2": None,
            "addressStackBlock": (">I", 0x00),
            "addressTTY": None,
        }
        self.HeuristicsFields = {**defaults, **self.HeuristicsFields}

    def Heuristics(self):
        self.RanHeuristics = True

        def get_last_max(index_data):
            singles = [
                v for d in index_data.values() if len(d) == 1 for v in d.values()
            ]
            return max(singles, default=0)

        sizes = sorted(
            (
                (size, get_last_max(indices))
                for size, indices in self.dProcessStructureStats.items()
            ),
            key=lambda x: x[1],
        )
        self.HeuristicsSize = sizes[-1][0]
        self.HeuristicsFields = {}
        self.HeuristicsStructureAnalysis()
        self.HeuristicsFindProcessName()
        self.HeuristicsFindQ()
        self.HeuristicsFindTy()
        self.HeuristicsAddMissingFields()


def GetAddressFromFilename(filename):
    match = re.search("-0x[0-9a-f]{8}$", filename, re.IGNORECASE)
    if match:
        return int(match.group(0)[3:], 16)
    return None
