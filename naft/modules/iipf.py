#!/usr/bin/env python3

__description__ = 'Network Appliance Forensic Toolkit - IOS Image Parsing Functions'
__version__ = '1.0.0b1'
__original_author__ = 'Didier Stevens'
__current_authors__ = '@digitalsleuth and @G-K7'
__date__ = '2021/03/05'

import os
import glob
import struct
from io import BytesIO
import zipfile
import hashlib
import naft.modules.uf as uf
import naft.modules.impf as impf

class cELFSection:

    def __init__(self, data, dataELF):
        self.data = data
        header = struct.unpack('>IIIIIIIIII', self.data)
        self.nameIndex = header[0]
        self.nameIndexString = ''
        self.type = header[1]
        self.flags = header[2]
        self.offset = header[4]
        self.size = header[5]
        if self.offset + self.size <= len(dataELF):
            self.sectionData = dataELF[self.offset : self.offset + self.size]
        else:
            self.sectionData = ''

    def GetHeader(self, offset=None, size=None):
        result = self.data[0:16]
        if offset == None:
            result += self.data[16:20]
        else:
            result += struct.pack('>I', offset)
        if size == None:
            result += self.data[20:24]
        else:
            result += struct.pack('>I', size)
        result += self.data[24:40]
        return result

class cELF:

    def __init__(self, data):
        self.data = data
        self.countSections = 0
        self.stringTableIndex = None
        self.Parse()

    def ParseELFHeader(self):
        if len(self.data) < 52:
            self.error = 1
            return
        if self.data[0:4] != b'\x7FELF': # ELF MAGIC number
            self.error = 2
            return
        if self.data[4] != 1: # 32-bit ELF header
            self.error = 3
            return
        if self.data[5] != 2: # MSB format
            self.error = 4
            return
        header = struct.unpack('>IIIIHHHHHH', self.data[24:52])
        self.addressEntry = header[0]
        self.programOffset = header[1]
        self.sectionOffset = header[2]
        if header[4] != 52: # ELF header size
            self.error = 5
            return
        if header[5] != 32: # program header size
            self.error = 6
            return
        if header[6] != 1: # number of program headers
            self.error = 7
            return
        if header[7] != 40: # section header size
            self.error = 8
            return
        self.countSections = header[8]
        self.stringTableIndex = header[9]

    def GetNullTerminatedString(self, index):
        result = ''
        while self.data[index] != 0:
            result += chr(self.data[index])
            index += 1
        return result

    def ParseSectionHeaders(self):
        if len(self.data) < self.sectionOffset + self.countSections * 40:
            self.error = 9
            return
        self.sections = []
        for index in range(self.countSections):
            self.sections.append(cELFSection(self.data[self.sectionOffset + index * 40:self.sectionOffset + (index + 1) * 40], self.data))
        if self.stringTableIndex == 0:
            dSectionNames = {0: '', 1: '.shstrtab', 11: '.text', 17: '.rodata', 25: '.sdata2', 33: '.data', 39: '.sdata', 46: '.sbss', 52: '.bss'}
            for oELFSection in self.sections:
                if oELFSection.nameIndex in dSectionNames:
                    oELFSection.nameIndexString = dSectionNames[oELFSection.nameIndex]
        else:
            for oELFSection in self.sections:
                oELFSection.nameIndexString = self.GetNullTerminatedString(self.sections[self.stringTableIndex].offset + oELFSection.nameIndex)

    def Parse(self):
        self.error = 0
        self.ParseELFHeader()
        if self.error == 0:
            self.ParseSectionHeaders()

    def GetHeader(self):
        return self.data[0:52]

    def GetProgramHeader(self, length):
        return self.data[self.programOffset:self.programOffset + 16] + struct.pack('>I', length) + struct.pack('>I', length + 0x10000) + self.data[self.programOffset + 24:self.programOffset + 32]

class cIOSImage:

    def __init__(self, data):
        self.data = data
        self.embeddedMD5 = None
        self.imageUncompressedName = None
        self.sizeUncompressed = None
        self.sizeCompressed = None
        self.checksumCompressed = None
        self.checksumUncompressed = None
        self.calculatedChecksumCompressed = None
        self.calculatedChecksumUncompressed = None
        self.imageUncompressed = None
        self.oCWStrings = None
        self.Parse()

    @classmethod
    def CalcChecksum(cls, data):
        sum = 0
        index = 0
        length = len(data)
        while length - index >= 4:
            sum += struct.unpack('>I', data[index:index + 4])[0]
            if sum > 0xFFFFFFFF:
                sum = (sum + 1) & 0xFFFFFFFF
            index += 4
#        if length - index != 0:
#            for x in data[index:]:
#                if x != '\x00':
#                    print('Warning: checksum data remainder not zero (%d)' % ord(x))
        return sum

    def ExtractEmbeddedMD5(self, data):
        index = data.find(impf.cCiscoMagic.STR_FADEFAD1)
        if index < 0:
            return None
        if index + len(impf.cCiscoMagic.STR_FADEFAD1) + 16 > len(data):
            return None
        return(''.join(['%02x' % ord(x) for x in data[index + len(impf.cCiscoMagic.STR_FADEFAD1):index + len(impf.cCiscoMagic.STR_FADEFAD1) + 16]]))

    def ExtractSections(self, oELF):
        oSectionHeaderCompressedImage = None
        oSectionHeaderEmbeddedMD5 = None
        oSectionHeaderCWStrings = None
        for oSectionHeader in oELF.sections:
            if oSectionHeader.sectionData[0:4] == impf.cCiscoMagic.STR_FEEDFACE:
                if oSectionHeaderCompressedImage != None:
                    print('Error: more than one FEEDFACE section')
                    self.error = 2
                else:
                    oSectionHeaderCompressedImage = oSectionHeader
            elif oSectionHeader.sectionData.find(impf.cCiscoMagic.STR_FADEFAD1) >= 0:
                if oSectionHeaderEmbeddedMD5 != None:
                    print('Error: more than one FADEFAD1 section')
                    self.error = 3
                else:
                    oSectionHeaderEmbeddedMD5 = oSectionHeader
            elif oSectionHeader.sectionData.find(impf.cCiscoMagic.STR_CW_BEGIN) >= 0:
                if oSectionHeaderCWStrings != None:
                    print('Error: more than one CW_ strings section')
                    self.error = 10
                else:
                    oSectionHeaderCWStrings = oSectionHeader
        return (oSectionHeaderCompressedImage, oSectionHeaderEmbeddedMD5, oSectionHeaderCWStrings)

    def Parse(self):
        self.error = 0
        self.oELF = cELF(self.data)
        if self.oELF.error != 0:
            self.error = 1
            print('ELF parsing error {:d}.'.format(self.oELF.error))
            if self.oELF.error <= 2:
                print('This is not an ELF file.')
            elif self.oELF.error < 5:
                print('This is probably not an ELF file/Cisco IOS image.')
            return
        self.oSectionHeaderCompressedImage, self.oSectionHeaderEmbeddedMD5, self.oSectionHeaderCWStrings = self.ExtractSections(self.oELF)
        if self.oSectionHeaderEmbeddedMD5 != None:
            self.embeddedMD5 = self.ExtractEmbeddedMD5(self.oSectionHeaderEmbeddedMD5.sectionData)
        if self.oSectionHeaderCWStrings != None:
            self.oCWStrings = impf.cCiscoCWStrings(self.oSectionHeaderCWStrings.sectionData)

        md5 = hashlib.md5()
        index = 0
        for oSectionHeader in self.oELF.sections:
            if index != 3 and index != 4:
                md5.update(oSectionHeader.sectionData)
            index += 1
        self.calculatedMD5 = md5.hexdigest()

        if self.oSectionHeaderCompressedImage == None:
            print('MAGIC number FEEDFACE not found')
            self.error = 4
            return
        self.sizeUncompressed, self.sizeCompressed, self.checksumCompressed, self.checksumUncompressed = struct.unpack('>IIII', self.oSectionHeaderCompressedImage.sectionData[len(impf.cCiscoMagic.STR_FEEDFACE):len(impf.cCiscoMagic.STR_FEEDFACE) + 4*4])
        zipData = self.oSectionHeaderCompressedImage.sectionData[len(impf.cCiscoMagic.STR_FEEDFACE) + 4*4:len(impf.cCiscoMagic.STR_FEEDFACE) + 4*4 + self.sizeCompressed]
        self.calculatedChecksumCompressed = cIOSImage.CalcChecksum(zipData)
        try:
            oZipFile = zipfile.ZipFile(BytesIO(zipData))
            try:
                names = oZipFile.namelist()
            except:
                self.error = 6
                print('Error retrieving ZIP namelist')
                oZipFile = None
        except:
            self.error = 5
            print('Error parsing ZIP section')
            oZipFile = None
        if oZipFile != None:
            if len(names) == 0:
                self.error = 7
                print('Error: no file found in ZIP')
            elif len(names) == 1:
                self.imageUncompressedName = names[0]
            else:
                self.error = 8
                print('More than one file found in ZIP')
                print(','.join(names))
            if self.imageUncompressedName != None:
                try:
                    self.imageUncompressed = oZipFile.open(self.imageUncompressedName).read()
                except:
                    self.error = 9
                    print('Error decompressing ZIP section')
                if self.imageUncompressed != None:
                    self.calculatedChecksumUncompressed = cIOSImage.CalcChecksum(self.imageUncompressed)

    def Print(self):
        print('IOS Image Metadata:\n')
        if self.oCWStrings != None and self.oCWStrings.error == None:
            for key in [b'CW_VERSION', b'CW_FAMILY', b'CW_FEATURE', b'CW_IMAGE', b'CW_SYSDESCR']:
                if key in self.oCWStrings.dCWStrings:
                    print('{}:{}{}'.format(key.decode('utf-8'), ' ' * (22 - len(key)), self.oCWStrings.dCWStrings[key].decode('utf-8')))

        booleanValue = {True: 'identical', False: 'DIFFERENT'}
        if self.oELF.error == 0:
            print('Entry point:           0x{:08X}'.format(self.oELF.addressEntry))
            print('Number of sections:    {:d}'.format(self.oELF.countSections))
            print('Embedded MD5:          {}'.format(uf.cn(self.embeddedMD5)))
            print('Calculated MD5:        {}'.format(uf.cn(self.calculatedMD5)))
            print('Compressed size:       {:d}'.format(uf.cn(self.sizeCompressed)))
            print('Checksum compressed:   0x{:08X}'.format(uf.cn(self.checksumCompressed)))
            print('Calculated checksum:   0x{:08X} ({})'.format(uf.cn(self.calculatedChecksumCompressed), booleanValue[self.checksumCompressed == self.calculatedChecksumCompressed]))
            print('Uncompressed size:     {:d}'.format(uf.cn(self.sizeUncompressed)))
            print('Image name:            {}'.format(uf.cn(self.imageUncompressedName)))
            print('Checksum uncompressed: 0x{:08X}'.format(uf.cn(self.checksumUncompressed)))
            print('Calculated checksum:   0x{:08X} ({})'.format(uf.cn(self.calculatedChecksumUncompressed), booleanValue[self.checksumUncompressed == self.calculatedChecksumUncompressed]))

    def Compress(self, filenameUncompressedImage, imageUncompressed):
        oStringIO = BytesIO()
        oZipFile = zipfile.ZipFile(oStringIO, 'w')
        oZipInfo = zipfile.ZipInfo(filenameUncompressedImage)
        oZipInfo.compress_type = zipfile.ZIP_DEFLATED
        oZipFile.writestr(oZipInfo, imageUncompressed)
        oZipFile.close()
        result = oStringIO.getvalue()
        oStringIO.close()
        result = impf.cCiscoMagic.STR_FEEDFACE + struct.pack('>IIII', len(imageUncompressed), len(result), cIOSImage.CalcChecksum(result), cIOSImage.CalcChecksum(imageUncompressed)) + result
        return result

    def Pack(self, filenameUncompressedImage, imageUncompressed):
        if self.oELF.countSections == 6:
            SFX = self.oELF.sections[0].sectionData + self.oELF.sections[1].sectionData + self.oELF.sections[2].sectionData + self.oELF.sections[3].sectionData
            imageCompressed = self.Compress(filenameUncompressedImage, imageUncompressed)
            imageNew = self.oELF.GetHeader()
            imageNew += self.oELF.GetProgramHeader(len(SFX) + len(imageCompressed) + len(self.oELF.sections[4].sectionData))
            imageNew += self.oELF.sections[0].GetHeader()
            imageNew += self.oELF.sections[1].GetHeader()
            imageNew += self.oELF.sections[2].GetHeader()
            imageNew += self.oELF.sections[3].GetHeader()
            lengthHeaders = len(imageNew) + 2 * len(self.oELF.sections[4].GetHeader())
            imageNew += self.oELF.sections[4].GetHeader(lengthHeaders + len(SFX) + len(imageCompressed), len(self.oELF.sections[4].sectionData))
            imageNew += self.oELF.sections[5].GetHeader(lengthHeaders + len(SFX), len(imageCompressed))
            imageNew += SFX
            imageNew += imageCompressed
            imageNew += self.oELF.sections[4].sectionData
            return imageNew
        elif self.oELF.countSections == 7:
            SFX = self.oELF.sections[0].sectionData + self.oELF.sections[1].sectionData + self.oELF.sections[2].sectionData + self.oELF.sections[3].sectionData  + self.oELF.sections[4].sectionData
            imageCompressed = self.Compress(filenameUncompressedImage, imageUncompressed)
            imageNew = self.oELF.GetHeader()
            imageNew += self.oELF.GetProgramHeader(len(SFX) + len(imageCompressed) + len(self.oELF.sections[5].sectionData))
            imageNew += self.oELF.sections[0].GetHeader()
            imageNew += self.oELF.sections[1].GetHeader()
            imageNew += self.oELF.sections[2].GetHeader()
            imageNew += self.oELF.sections[3].GetHeader()
            imageNew += self.oELF.sections[4].GetHeader()
            lengthHeaders = len(imageNew) + 2 * len(self.oELF.sections[5].GetHeader())
            imageNew += self.oELF.sections[5].GetHeader(lengthHeaders + len(SFX) + len(imageCompressed), len(self.oELF.sections[5].sectionData))
            imageNew += self.oELF.sections[6].GetHeader(lengthHeaders + len(SFX), len(imageCompressed))
            imageNew += SFX
            imageNew += imageCompressed
            imageNew += self.oELF.sections[5].sectionData
            return imageNew
        else:
            return None

    def ImageUncompressedIDAPro(self):
        newImage = self.imageUncompressed[0:18] + '\x00\x14'.encode() + self.imageUncompressed[20:] # Set machine to PowerPC 0x14
        return newImage

class cMD5Database():

    def __init__(self, directoryCSVFiles):
        self.dMD5Database = {}
        countDoubles = 0
        countMD5EmptyString = 0
        for filenameCSV in glob.glob(os.path.join(directoryCSVFiles, '*.csv')):
            result = self.AddCSV(filenameCSV)
            countDoubles += result[0]
            countMD5EmptyString += result[1]
        print('{} unique entries in md5 database, %d doubles of which {} empty string'.format(len(self.dMD5Database), countDoubles, countMD5EmptyString))

    def AddCSV(self, filenameCSV):
        countDoubles = 0
        countMD5EmptyString = 0
        md5EmptyString = hashlib.md5('').hexdigest()
        basename = os.path.basename(filenameCSV)
        for line in open(filenameCSV, 'r').readlines():
            md5hash, filename = line.strip('\n').split(',')
            md5hash = md5hash.lower()
            if md5hash in self.dMD5Database:
                if md5hash == md5EmptyString:
                    countMD5EmptyString += 1
                countDoubles += 1
            else:
                self.dMD5Database[md5hash] = (basename, filename.strip(' '))
        return (countDoubles, countMD5EmptyString)

    def Find(self, md5hash):
        if md5hash in self.dMD5Database:
            return self.dMD5Database[md5hash]
        else:
            return None, None

