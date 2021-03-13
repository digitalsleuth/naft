#!/usr/bin/env python3

__description__ = 'Network Appliance Forensic Toolkit - IOS Memory Parsing Functions'
__version__ = '1.0.0b1'
__original_author__ = 'Didier Stevens'
__current_authors__ = '@digitalsleuth and @G-K7'
__date__ = '2021/03/05'

import struct
import re
import naft.modules.uf as uf


class cCiscoMagic:
    STR_REGIONS      = b'\xDE\xAD\x12\x34'
    INT_BLOCK_BEGIN  = 0xAB1234CD
    STR_BLOCK_BEGIN  = b'\xAB\x12\x34\xCD'
    INT_BLOCK_CANARY = 0xFD0110DF
    INT_BLOCK_FREE   = 0xDEADBEEF
    STR_PROCESS_END  = b'\xBE\xEF\xCA\xFE'

    STR_FEEDFACE     = b'\xFE\xED\xFA\xCE'
    STR_FADEFAD1     = b'\xFA\xDE\xFA\xD1\x00\x00\x00\x18'

    STR_CW_DELIMITER = b'$'
    STR_CW_          = b'CW_'
    STR_CW_BEGIN     = STR_CW_ + b'BEGIN' + STR_CW_DELIMITER
    STR_CW_END       = STR_CW_ + b'END' + STR_CW_DELIMITER


class cIOSCoreDump:

    def __init__(self, coredumpFilename):
        self.coredumpFilename = coredumpFilename
        self.Parse()

    def Parse(self):
        self.error = None
        self.coredump = uf.File2Data(self.coredumpFilename)
        if self.coredump is None:
            self.error = 'Error reading coredump {}'.format(self.coredumpFilename)
            return
        indexRegionsMetaData = self.coredump.find(cCiscoMagic.STR_REGIONS)
        if indexRegionsMetaData < 0:
            self.error = 'Magic sequence {} not found'.format(cCiscoMagic.STR_REGIONS.hex().upper())
            return
        if self.coredump[indexRegionsMetaData + 4:indexRegionsMetaData + 4 + 4] != b'\x00\x00\x00\x05':
            self.error = 'Unexpected data found: {}'.format(self.coredump[indexRegionsMetaData + 4:indexRegionsMetaData + 4 + 4].hex())
            return
        addresses = struct.unpack('>IIII', self.coredump[indexRegionsMetaData + 20:indexRegionsMetaData + 20 + 4 * 4])
        indexHeap = self.coredump.find(cCiscoMagic.STR_BLOCK_BEGIN, addresses[3] - addresses[0])
        if indexHeap < 0:
            self.error = 'Magic sequence {} not found'.format(cCiscoMagic.STR_BLOCK_BEGIN.hex().upper())
            return
        self.address = addresses[0]
        self.size = len(self.coredump)
        addressBegin = self.address
        addressEnd = self.address + self.size
        regionsCalculation = list(map(lambda x, y: (x, y), ('begin', 'text', 'data', 'bss'), addresses))
        regionsCalculation.append(('heap', addresses[0] + indexHeap))
        regionsCalculation.append(('end', addressEnd))
        indices = list(range(len(regionsCalculation)))
        for index, value in enumerate(indices):
            address = regionsCalculation[value][1]
            if address < addressBegin or address > addressEnd:
                del indices[index]
            regionsCalculation[value] = (regionsCalculation[value][0], regionsCalculation[value][1], None, None)
        for index, value in enumerate(indices[:-1]):
            length = regionsCalculation[indices[index + 1]][1] - regionsCalculation[value][1]
            regionsCalculation[value] = (regionsCalculation[value][0], regionsCalculation[value][1], length, regionsCalculation[value][1] - addressBegin)
        self.regions = regionsCalculation[:-1]

    def Region(self, name):
        for region in self.regions:
            if region[0].lower() == name.lower():
                if region[2] is None:
                    return region[1], None
                else:
                    return region[1], self.coredump[region[3]:region[3] + region[2]]
        return None, None

    def RegionTEXT(self):
        return self.Region('text')

    def RegionDATA(self):
        return self.Region('data')

    def RegionBSS(self):
        return self.Region('bss')

    def RegionHEAP(self):
        return self.Region('heap')

    def GetString(self, address):
        index = address - self.address
        if index < 0 or index >= self.size:
            return None
        string = ''
        iter = 0
        while index + iter < self.size and self.coredump[index + iter] != 0 and iter < 50:
            string += chr(self.coredump[(index + iter)])
            iter += 1
        return string

    def GetInteger32(self, address):
        index = address - self.address
        if index < 0 or index - 4 >= self.size:
            return None
        return struct.unpack('>I', self.coredump[index:index + 4])[0]


class cIOSMemoryBlockHeader:

    def __init__(self, data, headerSize, index, baseAddress, oIOSMemoryParser):
        self.data = data
        self.error = 0
        self.headerSize = headerSize
        if len(data) != 0:
            if headerSize == 40:
                header = struct.unpack('>IIIIIIIIII', data[0:headerSize])
            elif headerSize == 48:
                header = struct.unpack('>IIIIIIIIIIII', data[0:headerSize])
            else:
                self.error = 1
                return
            if header[0] != cCiscoMagic.INT_BLOCK_BEGIN:
                self.error = 2
                return
            self.index = index
            self.address = index + baseAddress
            self.addressData = self.address + headerSize
            self.oIOSMemoryParser = oIOSMemoryParser
            self.PID = header[1]
            self.AllocCheck = header[2]
            self.AllocName = header[3]
            self.AllocNameResolved = ''
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
                freeHeader = struct.unpack('>IIIIII', data[headerSize:headerSize + 24])
                if freeHeader[0] != cCiscoMagic.INT_BLOCK_FREE:
                    self.error = 3
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
            self.error = 4
            return

    def ParseSizeField(self, value):
        free = value & 0x80000000 == 0x00000000
        size = (value & 0x7FFFFFFF) * 2
        return free, size

    def GetData(self):
        start = self.index + self.headerSize
        if struct.unpack('>I', self.oIOSMemoryParser.memory[start + self.BlockSize - 4:start + self.BlockSize])[0] == cCiscoMagic.INT_BLOCK_CANARY:
            return self.oIOSMemoryParser.memory[start:start + self.BlockSize - 4]
        else:
            return self.oIOSMemoryParser.memory[start:start + self.BlockSize]

    def GetRawData(self):
        return self.oIOSMemoryParser.memory[self.index:self.index + self.headerSize + self.BlockSize]

    def ShowLine(self):
        if self.AllocNameResolved == '' or self.AllocNameResolved is None:
            allocName = '{:08X}'.format(self.AllocName)
        else:
            allocName = self.AllocNameResolved
        if self.NextFree is None:
            NextFree = '--------'
        else:
            NextFree = '{:->8s}'.format('{:X}'.format(self.NextFree))
        if self.PrevFree is None:
            PrevFree = '--------'
        else:
            PrevFree = '{:->8s}'.format('{:X}'.format(self.PrevFree))
        return '{:08X} {:010d} {:08X} {:08X} {:03d} {} {} {:08X} {}'.format(self.address, self.BlockSize, self.PrevBlock, self.NextBlock, self.RefCnt, PrevFree, NextFree, self.AllocPC, allocName)
    ShowHeader = 'Address\t Bytes\t    PrevBlk  NextBlk  Ref PrevFree NextFree AllocPC  What'


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
        header = struct.unpack('>IIIIIIIIII', self.memory[0:self.headerSize])
        if header[0] != cCiscoMagic.INT_BLOCK_BEGIN:
            return False
        free, size = self.ParseSizeField(header[7])
        if self.length < self.headerSize + size + self.headerSize:
            return False
        header = struct.unpack('>IIIIIIIIII', self.memory[self.headerSize + size:self.headerSize + size + self.headerSize])
        if header[0] != cCiscoMagic.INT_BLOCK_BEGIN:
            self.headerSize = 48
            if self.length < self.headerSize + size + self.headerSize:
                return False
            header = struct.unpack('>IIIIIIIIIIII', self.memory[self.headerSize + size:self.headerSize + size + self.headerSize])
            if header[0] != cCiscoMagic.INT_BLOCK_BEGIN:
                return False
        self.baseAddress = header[6] - 0x14
        return True

    def ExtractHeaders(self):
        index = 0
        while True:
            oIOSMemoryBlockHeader = cIOSMemoryBlockHeader(self.memory[index:index + self.headerSize + 24], self.headerSize, index, self.baseAddress, self)
            if oIOSMemoryBlockHeader.error != 0:
                if oIOSMemoryBlockHeader.error == 4:
                    return False
                print('Error {:d}'.format(oIOSMemoryBlockHeader.error))
                return False
            self.Headers.append(oIOSMemoryBlockHeader)
            self.dHeadersAddressData[oIOSMemoryBlockHeader.addressData] = oIOSMemoryBlockHeader
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
                oIOSMemoryBlockHeader.AllocNameResolved = self.dResolvedNames[oIOSMemoryBlockHeader.AllocName]


class cCiscoCWStrings:

    def __init__(self, data):
        self.data = data
        self.error = None
        self.dCWStrings = {}
        begin = uf.FindAllStrings(self.data, cCiscoMagic.STR_CW_BEGIN)
        if len(begin) == 0:
            self.error = 'Error: CW_BEGIN not found'
            return
        elif len(begin) > 1:
            self.error = 'Error: CW_BEGIN found multiple times'
            return
        end = uf.FindAllStrings(self.data, cCiscoMagic.STR_CW_END)
        if len(end) == 0:
            self.error = 'Error: CW_END not found'
            return
        elif len(end) > 1:
            self.error = 'Error: CW_END found multiple times'
            return
        if begin[0] >= end[0]:
            self.error = 'Error: CW_BEGIN not before CW_END'
            return
        finalDelimiter = self.data.find(cCiscoMagic.STR_CW_DELIMITER, end[0] + len(cCiscoMagic.STR_CW_END))
        if finalDelimiter < 0:
            self.error = 'Error: final delimiter $ not found'
            return
        cwStrings = self.data[begin[0]:finalDelimiter + 1]
        for index in uf.FindAllStrings(cwStrings, cCiscoMagic.STR_CW_):
            startCWString = cwStrings[index:]
            delimiters = uf.FindAllStrings(startCWString, cCiscoMagic.STR_CW_DELIMITER)
            if len(delimiters) < 2:
                self.error = 'Error: delimiters $ not found'
                return
            self.dCWStrings[startCWString[0:delimiters[0]]] = startCWString[delimiters[0] + 1:delimiters[1]]


class cIOSProcess:

    dFields = {
                692: {
                        'addressProcessName': ('>I', 0xD0),
                        'PC':                 ('>I', 0x6C),
                        'Q':                  ('>I', 0xD4),
                        'Ty':                 ('>I', 0x64),
                        'Runtime':            ('>I', 0xB8),
                        'Invoked':            ('>I', 0xC8),
                        'Stack1':             ('>I', 0xEC),
                        'Stack2':             ('>I', 0xF0),
                        'addressStackBlock':  ('>I', 0x00),
                        'addressTTY':         ('>I', 0xF8),
                     },
                696: {
                        'addressProcessName': ('>I', 0xE8),
                        'PC':                 ('>I', 0x90),
                        'Q':                  ('>I', 0xEC),
                        'Ty':                 ('>I', 0x88),
                        'Runtime':            ('>I', 0xD8),
                        'Invoked':            ('>I', 0xE0),
                        'Stack1':             ('>I', 0x100),
                        'Stack2':             ('>I', 0x104),
                        'addressStackBlock':  ('>I', 0x00),
                        'addressTTY':         ('>I', 0xC4),
                     },
                712: {
                        'addressProcessName': ('>I', 0xE8),
                        'PC':                 ('>I', 0x90),
                        'Q':                  ('>I', 0xEC),
                        'Ty':                 ('>I', 0x88),
                        'Runtime':            ('>I', 0xD0),
                        'Invoked':            ('>I', 0xE0),
                        'Stack1':             ('>I', 0x100),
                        'Stack2':             ('>I', 0x104),
                        'addressStackBlock':  ('>I', 0x00),
                        'addressTTY':         ('>I', 0xC4),
                     },
                732: {
                        'addressProcessName': ('>I', 0xF8),
                        'PC':                 ('>I', 0x90),
                        'Q':                  ('>I', 0xFC),
                        'Ty':                 ('>I', 0x88),
                        'Runtime':            ('>I', 0xE0),
                        'Invoked':            ('>I', 0xF0),
                        'Stack1':             ('>I', 0x114),
                        'Stack2':             ('>I', 0x118),
                        'addressStackBlock':  ('>I', 0x00),
                        'addressTTY':         ('>I', 0xCC),
                     },
                744: {
                        'addressProcessName': ('>I', 0xD8),
                        'PC':                 ('>I', 0x70),
                        'Q':                  ('>I', 0xDC),
                        'Ty':                 ('>I', 0x68),
                        'Runtime':            ('>I', 0xC0),
                        'Invoked':            ('>I', 0xD0),
                        'Stack1':             ('>I', 0xF8),
                        'Stack2':             ('>I', 0xFC),
                        'addressStackBlock':  ('>I', 0x00),
                        'addressTTY':         ('>I', 0x100),
                     },
              }

    def __init__(self, processID, data, oIOSCoreDump=None, dProcessStructureStats={}, dHeuristicsFields={}):
        if dHeuristicsFields != {}:
            for key, value in dHeuristicsFields.items():
                self.dFields[key] = value
        self.error = ''
        self.processID = processID
        self.data = data
        self.indexProcessEnd = self.data.find(cCiscoMagic.STR_PROCESS_END, 690, len(data))  # BEEFCAFE can appear early in the process as well, parse for one near end of known range
        if self.indexProcessEnd < 0:
            self.error = 'Error: parsing process structure, BEEFCAFE not found'
            return
        if not self.IsSupportedProcessStructure():
            self.addressProcessName = None
            self.error = 'Error: unexpected process structure, length = {:d}'.format(self.indexProcessEnd)
        else:
            self.SetFields()
            if self.Q is None:
                self.Q_str = '?'
            else:
                self.Q_str = cIOSProcess.Q2Str(self.Q)
            if self.Ty is None:
                self.Ty_str = '?'
            else:
                self.Ty_str = cIOSProcess.Ty2Str(self.Ty)
            addressIter = self.addressStackBlock
            while oIOSCoreDump.GetInteger32(addressIter) == 0xFFFFFFFF and addressIter - self.addressStackBlock <= self.Stack2:
                addressIter += 4
            self.LowWaterMark = addressIter - self.addressStackBlock
            if self.addressTTY is None:
                self.TTY = None
            elif self.addressTTY == 0:
                self.TTY = 0
            else:
                if oIOSCoreDump is None:
                    self.TTY = None
                else:
                    self.TTY = oIOSCoreDump.GetInteger32(self.addressTTY+4)
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
            exec('self.{} = None'.format(fieldName))
        else:
            format, position = self.dFields[self.indexProcessEnd][fieldName]
            fieldValue = struct.unpack(format, self.data[position:position + 4])[0]
            exec('self.{} = fieldValue'.format(fieldName))

    def SetFields(self):
        for fieldName in self.dFields[self.indexProcessEnd]:
            self.SetField(fieldName)

    @classmethod
    def Q2Str(cls, number):
        dPriorities = {2: 'C', 3: 'H', 4: 'M', 5: 'L'}
        # dPriorities = {1:'C', 2:'H', 3:'M', 4:'L'} #a# regression test this
        if number in dPriorities:
            return dPriorities[number]
        else:
            return str(number)

    @classmethod
    def Ty2Str(cls, number):
        # dTys = {0:'*', 4:'we', 6:'si', 7:'sp', 8:'st'}
        dTys = {0: '*', 1: 'E', 2: 'S', 3: 'rd', 4: 'we', 5: 'sa', 6: 'si', 7: 'sp', 8: 'st', 9: 'hg', 10: 'xx'}  # untested
        if number in dTys:
            return dTys[number]
        else:
            return str(number)

    def CalcProcessStructureStats(self, dStats):
        for index, integer32 in enumerate(struct.unpack('>' + 'I' * int(len(self.data) / 4), self.data)):
            if index in dStats:
                bucket = dStats[index]
                if integer32 in bucket:
                    bucket[integer32] += 1
                else:
                    bucket[integer32] = 1
            else:
                dStats[index] = {integer32: 1}

    def Line(self):
        line = '{:4d} {}{:<2} '.format(self.processID, self.Q_str, self.Ty_str)
        if self.PC is None:
            line += '???????? '
        else:
            line += '{:08X} '.format(self.PC)
        if self.Runtime is None:
            line += '       ? '
        else:
            line += '    {:8d} '.format(self.Runtime)
        if self.Invoked is None:
            line += '       ? '
        else:
            line += '  {:8d} '.format(self.Invoked)
        if self.Invoked == 0 or self.Invoked is None or self.Runtime is None:
            line += '      ?'
        else:
            line += '{:7d}'.format(int(self.Runtime * 1000 / self.Invoked))
        if self.LowWaterMark is None:
            line += '    ?/'
        else:
            line += '{:5d}/'.format(self.LowWaterMark)
        if self.Stack2 is None:
            line += '?     '
        else:
            line += '{:<5d} '.format(self.Stack2)
        if self.TTY is None:
            line += ' ? '
        else:
            line += '{:>2d} '.format(self.TTY)
        if self.addressStackBlock is None:
            line += '       ? '
        else:
            line += '{:08X} '.format(self.addressStackBlock)
        line += uf.cn(self.name)
        return line


class cIOSCoreDumpAnalysis:

    def __init__(self, coredumpFilename):
        self.error = None
        self.RanHeuristics = False
        self.oIOSCoreDump = cIOSCoreDump(coredumpFilename)
        if self.oIOSCoreDump.error is not None:
            self.error = self.oIOSCoreDump.error
            return
        addressHeap, memoryHeap = self.oIOSCoreDump.RegionHEAP()
        if memoryHeap is None:
            self.error = 'Heap region not found'
            return
        oIOSMemoryParser = cIOSMemoryParser(memoryHeap)
        oIOSMemoryParser.ResolveNames(self.oIOSCoreDump)
        dProcessArray = {}
        oLastProcessArray = None
        for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
            if oIOSMemoryBlockHeader.AllocNameResolved == 'Process Array':
                processArray = oIOSMemoryBlockHeader.GetData()
                addressNextProcessArray = struct.unpack('>I', processArray[0:4])[0]
                if addressNextProcessArray == 0:
                    oLastProcessArray = oIOSMemoryBlockHeader
                else:
                    dProcessArray[addressNextProcessArray] = oIOSMemoryBlockHeader
        oIterProcessArray = oLastProcessArray
        addressProcesses = []
        while oIterProcessArray is not None:
            processArray = oIterProcessArray.GetData()
            countProcessesInThisArray = struct.unpack('>I', processArray[4:8])[0]
            addressProcessesInThisArray = []
            for addressProcess in struct.unpack('>' + 'I' * int(len(processArray[8:]) / 4), processArray[8:]):
                if countProcessesInThisArray > 0:
                    addressProcessesInThisArray.append(addressProcess)
                    if addressProcess != 0:
                        countProcessesInThisArray -= 1
            addressProcessesInThisArray.extend(addressProcesses)
            addressProcesses = addressProcessesInThisArray
            addressProcessArray = oIterProcessArray.addressData
            if addressProcessArray in dProcessArray:
                oIterProcessArray = dProcessArray[addressProcessArray]
            else:
                oIterProcessArray = None
        self.processes = []
        self.dProcessStructureStats = {}
        countProcessStructureErrors = 0
        for index, addressProcess in enumerate(addressProcesses):
            if addressProcess != 0:
                if addressProcess in oIOSMemoryParser.dHeadersAddressData:
                    oIOSProcess = cIOSProcess(index + 1, oIOSMemoryParser.dHeadersAddressData[addressProcess].GetData(), self.oIOSCoreDump, self.dProcessStructureStats)
                    if oIOSProcess.error.startswith('Error: unexpected process structure, length ='):
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
                        oIOSProcess = cIOSProcess(index + 1,
                                                  oIOSMemoryParser.dHeadersAddressData[addressProcess].GetData(),
                                                  self.oIOSCoreDump,
                                                  self.dProcessStructureStats,
                                                  {self.HeuristicsSize: self.HeuristicsFields})
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
                    if filteredMin >= region[1] and filteredMin <= region[1] + region[2] - 1:
                        if not region[0] in regionNames:
                            regionNames.append(region[0])
                    if unfilteredMax >= region[1] and unfilteredMax <= region[1] + region[2] - 1:
                        if not region[0] in regionNames:
                            regionNames.append(region[0])
            regionNames.sort()
            self.dHeuristicsAnalysis[key1] = (countKeys, min(dStats[key1]), filteredMin, unfilteredMax, regionNames, dStats[key1])
#        keys1 = self.dHeuristicsAnalysis.keys()
#        keys1.sort()
#        for key1 in keys1:
#            regionName = ' '.join(self.dHeuristicsAnalysis[key1][4])
#            keys2 = self.dHeuristicsAnalysis[key1][5].keys()
#            keys2.sort()
#            if self.dHeuristicsAnalysis[key1][0] > 2 and self.dHeuristicsAnalysis[key1][0] <= 7:
#                bucket = '-> ' + ' '.join(['%X:%d' % (key2, self.dHeuristicsAnalysis[key1][5][key2]) for key2 in keys2])
#            else:
#                bucket = ''
#            print('%3d %3X: %3d %08X %08X %08X %s %s' % (key1, key1*4, self.dHeuristicsAnalysis[key1][0], self.dHeuristicsAnalysis[key1][1], self.dHeuristicsAnalysis[key1][2], self.dHeuristicsAnalysis[key1][3], regionName, bucket))

    def HeuristicsFindProcessName(self):
        countMax = 0
        keyMax = None
        for key1 in self.dHeuristicsAnalysis:
            if 'data' in self.dHeuristicsAnalysis[key1][4] and self.dHeuristicsAnalysis[key1][1] != 0 and key1 > 1 and self.dHeuristicsAnalysis[key1][0] > countMax:
                countMax = self.dHeuristicsAnalysis[key1][0]
                keyMax = key1
        if keyMax is not None:
            self.HeuristicsFields['addressProcessName'] = ('>I', keyMax*4)

    def HeuristicsFindQ(self):
        keyFound = None
        for key1 in self.dHeuristicsAnalysis:
            if self.dHeuristicsAnalysis[key1][0] > 1 and self.dHeuristicsAnalysis[key1][1] >= 2 and self.dHeuristicsAnalysis[key1][3] <= 5:
                if keyFound is None:
                    keyFound = key1
                else:
                    return
        if keyFound is not None:
            self.HeuristicsFields['Q'] = ('>I', keyFound*4)

    def HeuristicsFindTy(self):
        keyFound = None
        for key1 in self.dHeuristicsAnalysis:
            if (self.dHeuristicsAnalysis[key1][0] > 1 and
                    self.dHeuristicsAnalysis[key1][1] == 0 and
                    self.dHeuristicsAnalysis[key1][5][0] <= 2 and
                    self.dHeuristicsAnalysis[key1][3] >= 4 and
                    self.dHeuristicsAnalysis[key1][3] <= 10):
                if keyFound is None:
                    keyFound = key1
                else:
                    return
        if keyFound is not None:
            self.HeuristicsFields['Ty'] = ('>I', keyFound*4)

    def HeuristicsAddMissingFields(self):
        dFields = {
                    'addressProcessName': None,
                    'PC':                 None,
                    'Q':                  None,
                    'Ty':                 None,
                    'Runtime':            None,
                    'Invoked':            None,
                    'Stack1':             None,
                    'Stack2':             None,
                    'addressStackBlock':  ('>I', 0x00),
                    'addressTTY':         None,
                  }
        for field in dFields:
            if field not in self.HeuristicsFields:
                self.HeuristicsFields[field] = dFields[field]

    def Heuristics(self):
        self.RanHeuristics = True
        sizes = []
        for size in self.dProcessStructureStats:
            lastMax = 0
            for index in self.dProcessStructureStats[size]:
                if len(self.dProcessStructureStats[size][index]) == 1:
                    if lastMax < list(self.dProcessStructureStats[size][index].values())[0]:
                        lastMax = list(self.dProcessStructureStats[size][index].values())[0]
            sizes.append((size, lastMax))
        sizes.sort(key=lambda x: x[1])
        self.HeuristicsSize = sizes[-1][0]
        self.HeuristicsFields = {}
        self.HeuristicsStructureAnalysis()
        self.HeuristicsFindProcessName()
        self.HeuristicsFindQ()
        self.HeuristicsFindTy()
        self.HeuristicsAddMissingFields()
#        print({self.HeuristicsSize:self.HeuristicsFields})


def GetAddressFromFilename(filename):
    match = re.search("-0x[0-9a-f]{8}$", filename, re.IGNORECASE)
    if match:
        return int(match.group(0)[3:], 16)
    else:
        return None
