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
from concurrent.futures import ProcessPoolExecutor
import naft.modules.uf as uf
import naft.modules.iipf as iipf
import time
import re
import naft.modules.impf as impf


def inProgress(function, obj):
    animation = "|/-\\"
    idx = 0
    pool = ProcessPoolExecutor(3)
    future = pool.submit(function, (obj))

    while not future.done():
        print("Processing... "+animation[idx % len(animation)], end="\r")
        idx += 1
        time.sleep(0.1)

    return future.result()

def CiscoIOSImageFileParser(filename, arguments):
    global oMD5Database

    image = uf.File2Data(filename)
    if image == None:
        print('Error reading {}'.format(filename))
        return

    oIOSImage = inProgress(iipf.cIOSImage, image)
    oIOSImage.Print()

    if arguments['md5db']:
        if arguments['md5db'] != None:
            oMD5Database = cMD5Database(arguments['md5db'])
        md5hash = hashlib.md5(image).hexdigest()
        filenameCSV, filenameDB = oMD5Database.Find(md5hash)
        if filenameCSV == None:
            print('File not found in md5 database')
        else:
            print('File found in md5 database {} {}'.format(filenameCSV, filenameDB))

    if arguments['verbose']:
        print('\nELF Headers:\n')
        print(f"index {'index_str': >10} {'type': >10} {'flags': >10} {'offset': >10} {'size': >10} {'data': >10}")
        for oSectionHeader in oIOSImage.oELF.sections:
            print('   {:2d}    {:->7s} {:>10d} {:10d}   {:08X} {:>10d}       {}'.format(
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

def GlobRecurse(filewildcard):
    filenames = []
    directory = os.path.dirname(filewildcard)
    if directory == '':
        directory = '.'
    for entry in os.listdir(directory):
        if os.path.isdir(os.path.join(directory, entry)):
            filenames.extend(GlobRecurse(os.path.join(directory, entry, os.path.basename(filewildcard))))
    filenames.extend(glob.glob(filewildcard))
    return filenames

def GlobFilelist(filewildcard, arguments):
    if arguments['recurse']:
        return GlobRecurse(filewildcard)
    else:
        return glob.glob(filewildcard)

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

def CiscoIOSImageFileScanner(filewildcard, arguments):
    if not arguments['resume']:
        filenames = GlobFilelist(filewildcard, arguments)
        print('Target directory: /{}'.format('/'.join(re.split(r'[/\\]+', filenames[0])[:-1])))
        countFilenames = len(filenames)
        print(f"Performing scan on {countFilenames} file(s).\n")
        counter = 1
        if arguments['log'] != None:
            f = open(arguments['log'], 'w')
            f.close()
    else:
        fPickle = open(arguments['resume'], 'rb')
        filenames, countFilenames, counter = pickle.load(fPickle)
        fPickle.close()
        print('Pickle file loaded')

    while len(filenames) > 0:
        filename = filenames[0]
        try:
            line = [str(counter), str(countFilenames), re.split(r'[/\\]+',filename)[-1]]
            image = uf.File2Data(filename)
            if image == None:
                line.extend(['Error reading'])
            else:
                oIOSImage = inProgress(iipf.cIOSImage, image)
                if oIOSImage.oCWStrings != None and oIOSImage.oCWStrings.error == None:
                    line.extend([(uf.cn(vn(oIOSImage.oCWStrings.dCWStrings, b'CW_VERSION'))).decode(), (uf.cn(vn(oIOSImage.oCWStrings.dCWStrings, b'CW_FAMILY'))).decode()])
                else:
                    line.extend([uf.cn(None), uf.cn(None)])
                line.extend([
                    str(len(image)),
                    '{:.2f}'.format(Entropy(image)),
                    str(oIOSImage.error),
                    str(oIOSImage.oELF.error),
                    str(oIOSImage.oELF.countSections),
                    str(uf.cn(oIOSImage.oELF.stringTableIndex)),
                    uf.cn(oIOSImage.checksumCompressed, '0x%08X'),
                    str(oIOSImage.checksumCompressed != None and \
                    oIOSImage.checksumCompressed == oIOSImage.calculatedChecksumCompressed),
                    uf.cn(oIOSImage.checksumUncompressed, '0x%08X'),
                    str(oIOSImage.checksumUncompressed != None and \
                    oIOSImage.checksumUncompressed == oIOSImage.calculatedChecksumUncompressed),
                    uf.cn(oIOSImage.imageUncompressedName),
                    uf.cn(oIOSImage.embeddedMD5)
                ])
                if arguments['md5db']:
                    md5hash = hashlib.md5(image).hexdigest()
                    filenameCSV, filenameDB = oMD5Database.Find(md5hash)
                    line.extend([md5hash, uf.cn(filenameCSV), uf.cn(filenameDB)])
            strLine = ','.join(line)
            print(strLine)
            if arguments['log'] != None:
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
    print("")
    print(f"{counter-1} file(s) scanned.")
