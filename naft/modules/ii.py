#!/usr/bin/env python3

__description__ = 'Network Appliance Forensic Toolkit - IOS Image'
__version__ = '1.0.0b1'
__original_author__ = 'Didier Stevens'
__current_authors__ = '@digitalsleuth and @G-K7'
__date__ = '2021/03/05'

import hashlib
import glob
import os
import math
import pickle
import traceback
import time
import re
from pathlib import Path
import naft.modules.uf as uf
import naft.modules.iipf as iipf
import naft.modules.impf as impf


def CiscoIOSImageFileParser(filename, arguments):
    global oMD5Database
    image = uf.File2Data(filename)
    if image is None:
        print('Error reading {}'.format(filename))
        return
    oIOSImage = uf.InProgress(iipf.cIOSImage, image, filename)
    oIOSImage.Print()
    if arguments['md5db']:
        if arguments['md5db'] is not None:
            oMD5Database = iipf.cMD5Database(arguments['md5db'], arguments['scan'])
        md5hash = hashlib.md5(image).hexdigest()
        filenameCSV, filenameDB, filedateDB = oMD5Database.Find(md5hash)
        if filenameCSV is None:
            print('File not found in md5 database')
        else:
            print('File found in md5 database: {}, filename: {}, dated: {}'.format(filenameCSV, filenameDB, filedateDB))
    if arguments['verbose']:
        print('\nELF Headers:\n')
        print(f"index {'index_str': >10} {'type': >10} {'flags': >10} {'offset': >10} {'size': >10} {'data': >10}")
        for oSectionHeader in oIOSImage.oELF.sections:
            print('   {:2d}    {:>7s} {:>10d} {:10d}   {:08X} {:>10d}       {}'.format(
                oSectionHeader.nameIndex,
                oSectionHeader.nameIndexString,
                oSectionHeader.type,
                oSectionHeader.flags,
                oSectionHeader.offset,
                oSectionHeader.size,
                repr(oSectionHeader.sectionData[0:8]))
            )
    if arguments['extract']:
        print("\n{} written to: {}".format(oIOSImage.imageUncompressedName, arguments['extract']))
        uf.Data2File(oIOSImage.imageUncompressed, oIOSImage.imageUncompressedName, arguments['extract'])
    if arguments['ida']:
        print("\nPatching for IDA Pro...")
        time.sleep(0.5)
        print("{} written to: {}".format(oIOSImage.imageUncompressedName, arguments['ida']))
        uf.Data2File(oIOSImage.ImageUncompressedIDAPro(), oIOSImage.imageUncompressedName, arguments['ida'])


def Entropy(data):
    result = 0.0
    size = len(data)
    if size != 0:
        bucket = [0]*256
        for char in data:
            bucket[char] += 1
        for count in bucket:
            if count > 0:
                percentage = float(count) / size
                result -= percentage*math.log(percentage, 2)
    return result


def TargetDir(dir, arguments):
    bins = []
    tdir = Path(dir)
    R = False
    if tdir.is_dir():
        if arguments['recurse']:
            R = True
            for child in tdir.rglob('*'):
                if child.is_file() and child.suffix == '.bin':
                    bins.append(child)
        else:
            for child in tdir.iterdir():
                if child.is_file() and child.suffix == '.bin':
                    bins.append(child)
    if tdir.is_file() and tdir.suffix == '.bin':
        bins.append(tdir)
    return tdir, bins, R


def vn(dictionary, key):
    if key in dictionary:
        return dictionary[key]
    else:
        return None


def PickleData(data):
    fPickle = open('resume.pkl', 'wb')
    pickle.dump(data, fPickle)
    fPickle.close()
    print('Pickle file saved')


def CiscoIOSImageFileScanner(dir, arguments):
    if not arguments['resume']:
        tdir, filenames, R = TargetDir(dir, arguments)
        if not filenames:
            print('No image(s) found. Verify FILE/DIR path.')
            return
        print('Target path: {}'.format(tdir.resolve()))
        if arguments['recurse'] and R == True:
            print('Recursive search')
        countFilenames = len(filenames)
        print("Performing scan on {:d} file(s):\n".format(countFilenames))
        counter = 1
        if arguments['log'] is not None:
            f = open(arguments['log'], 'w')
            f.close()
    else:
        fPickle = open(arguments['resume'], 'rb')
        filenames, countFilenames, counter = pickle.load(fPickle)
        fPickle.close()
        print('Pickle file loaded')
    scan_header = [
        '#',
        'filename',
        'CW_VERSION',
        'CW_FAMILY',
        'imageSize',
        'entropy',
        'errorCode',
        'oELFerrorCode',
        'oELFsectionCount',
        'oELFstringTableIndex',
        'cksumCompressed',
        'cksumCompEqCalculated',
        'cksumUncompressed',
        'cksumUncompEqCalculated',
        'uncompressedFilename',
        'embeddedMD5'
        ]
    if arguments['md5db']:
        scan_header.extend(['md5hash', 'csvFilename', 'dbFilename', 'dbFileDate'])
    print(','.join(scan_header))
    while len(filenames) > 0:
        filename = filenames[0]
        try:
            line = [str(counter), str(filename.name)]
            image = uf.File2Data(filename)
            if image is None:
                line.extend(['Error reading'])
            else:
                oIOSImage = uf.InProgress(iipf.cIOSImage, image, filename.name)
                if oIOSImage.oCWStrings is not None and oIOSImage.oCWStrings.error is None:
                    line.extend([(uf.cn(vn(oIOSImage.oCWStrings.dCWStrings, b'CW_VERSION'))).decode(),
                                 (uf.cn(vn(oIOSImage.oCWStrings.dCWStrings, b'CW_FAMILY'))).decode()])
                else:
                    line.extend([uf.cn(None), uf.cn(None)])
                if oIOSImage.checksumCompressed is None:
                    checksumCompressed = 'Not found'
                else:
                    checksumCompressed = '0x{:08X}'.format(oIOSImage.checksumCompressed)
                if oIOSImage.checksumUncompressed is None:
                    checksumUncompressed = 'Not found'
                else:
                    checksumUncompressed = '0x{:08X}'.format(oIOSImage.checksumUncompressed)
                line.extend([
                    str(len(image)),
                    '{:.2f}'.format(Entropy(image)),
                    str(oIOSImage.error),
                    str(oIOSImage.oELF.error),
                    str(oIOSImage.oELF.countSections),
                    str(uf.cn(oIOSImage.oELF.stringTableIndex)),
                    str(uf.cn(oIOSImage.checksumCompressed, '0x{:08X}')),
                    str(oIOSImage.checksumCompressed is not None and
                        oIOSImage.checksumCompressed == oIOSImage.calculatedChecksumCompressed),
                    str(uf.cn(oIOSImage.checksumUncompressed, '0x{:08X}')),
                    str(oIOSImage.checksumUncompressed is not None and
                        oIOSImage.checksumUncompressed == oIOSImage.calculatedChecksumUncompressed),
                    uf.cn(oIOSImage.imageUncompressedName),
                    uf.cn(oIOSImage.embeddedMD5)
                ])
                if arguments['md5db']:
                    oMD5Database = iipf.cMD5Database(arguments['md5db'], arguments['scan'])
                    md5hash = hashlib.md5(image).hexdigest()
                    filenameCSV, filenameDB, filedateDB = oMD5Database.Find(md5hash)
                    line.extend([md5hash, uf.cn(filenameCSV), uf.cn(filenameDB), uf.cn(filedateDB)])
            strLine = ','.join(line)
            print(strLine)
            if arguments['log'] is not None:
                f = open(arguments['log'], 'a')
                f.write(strLine + '\n')
                f.close()
            counter += 1
            filenames = filenames[1:]
        except KeyboardInterrupt:
            print('KeyboardInterrupt')
            PickleData([filenames, countFilenames, counter])
            return
        except:
            traceback.print_exc()
            PickleData([filenames, countFilenames, counter])
            return
    print('')
    print('{:d} file(s) scanned.'.format(counter-1))
