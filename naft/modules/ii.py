#!/usr/bin/env python3

__description__ = "Network Appliance Forensic Toolkit - IOS Image"
__version__ = "1.0.2"
__original_author__ = "Didier Stevens"
__current_authors__ = "@digitalsleuth and @G-K7"
__date__ = "2026/06/29"

import hashlib
import math
import pickle
import traceback
import time
from pathlib import Path
import naft.modules.uf as uf
import naft.modules.iipf as iipf


oMD5Database = None


def CiscoIOSImageFileParser(filename, arguments):
    global oMD5Database
    image = uf.File2Data(filename)
    if image is None:
        print(f"Error reading {filename}")
        return
    oIOSImage = uf.InProgress(iipf.cIOSImage, image, filename)
    oIOSImage.Print()
    if arguments["md5db"]:
        if arguments["md5db"] is not None:
            oMD5Database = iipf.cMD5Database(arguments["md5db"], arguments["scan"])
        md5hash = hashlib.md5(image).hexdigest()
        filenameCSV, filenameDB, filedateDB = oMD5Database.Find(md5hash)
        if filenameCSV is None:
            print("File not found in md5 database")
        else:
            print(
                f"File found in md5 database: {filenameCSV}, filename: {filenameDB}, dated: {filedateDB}"
            )
    if arguments["verbose"]:
        print("\nELF Headers:\n")
        print(
            f"index {'index_str': >10} {'type': >10} {'flags': >10} {'offset': >10} {'size': >10} {'data': >10}"
        )
        for oSectionHeader in oIOSImage.oELF.sections:
            print(
                f"   {oSectionHeader.nameIndex:2d}    {oSectionHeader.nameIndexString:>7s} {oSectionHeader.type:>10d} {oSectionHeader.flags:10d}   {oSectionHeader.offset:08X} {oSectionHeader.size:>10d}       {repr(oSectionHeader.sectionData[0:8])}"
            )
    if arguments["extract"]:
        print(f"\n{oIOSImage.imageUncompressedName} written to: {arguments['extract']}")
        uf.Data2File(
            oIOSImage.imageUncompressed,
            oIOSImage.imageUncompressedName,
            arguments["extract"],
        )
    if arguments["ida"]:
        print("\nPatching for IDA Pro...")
        time.sleep(0.5)
        print(f"{oIOSImage.imageUncompressedName} written to: {arguments['ida']}")
        uf.Data2File(
            oIOSImage.ImageUncompressedIDAPro(),
            oIOSImage.imageUncompressedName,
            arguments["ida"],
        )


def Entropy(data):
    result = 0.0
    size = len(data)
    if size != 0:
        bucket = [0] * 256
        for char in data:
            bucket[char] += 1
        for count in bucket:
            if count > 0:
                percentage = float(count) / size
                result -= percentage * math.log(percentage, 2)
    return result


def TargetDir(directory, arguments):
    bins = []
    tdir = Path(directory)
    R = False
    if tdir.is_dir():
        if arguments["recurse"]:
            R = True
            for child in tdir.rglob("*"):
                if child.is_file() and child.suffix == ".bin":
                    bins.append(child)
        else:
            for child in tdir.iterdir():
                if child.is_file() and child.suffix == ".bin":
                    bins.append(child)
    if tdir.is_file() and tdir.suffix == ".bin":
        bins.append(tdir)
    return tdir, bins, R


def vn(dictionary, key):
    if key in dictionary:
        return dictionary[key]
    return None


def PickleData(data):
    with open("resume.pkl", "wb") as fPickle:
        pickle.dump(data, fPickle)
    print("Pickle file saved")


def CiscoIOSImageFileScanner(directory, arguments):
    global oMD5Database
    if not arguments["resume"]:
        tdir, filenames, R = TargetDir(directory, arguments)
        if not filenames:
            print("No image(s) found. Verify FILE/DIR path.")
            return
        print(f"Target path: {tdir.resolve()}")
        if arguments["recurse"] and R is True:
            print("Recursive search")
        countFilenames = len(filenames)
        print(f"Performing scan on {countFilenames:d} file(s):\n")
        counter = 1
    else:
        with open(arguments["resume"], "rb") as fPickle:
            filenames, countFilenames, counter = pickle.load(fPickle)
        print("Pickle file loaded")
    scan_header = [
        "#",
        "filename",
        "CW_VERSION",
        "CW_FAMILY",
        "imageSize",
        "entropy",
        "errorCode",
        "oELFerrorCode",
        "oELFsectionCount",
        "oELFstringTableIndex",
        "cksumCompressed",
        "cksumCompEqCalculated",
        "cksumUncompressed",
        "cksumUncompEqCalculated",
        "uncompressedFilename",
        "embeddedMD5",
    ]
    if arguments["md5db"]:
        scan_header.extend(["md5hash", "csvFilename", "dbFilename", "dbFileDate"])
    print(",".join(scan_header))
    if arguments["md5db"]:
        oMD5Database = iipf.cMD5Database(arguments["md5db"], arguments["scan"])

    interrupted = False

    def run_scan(log_file=None):
        nonlocal counter, filenames, interrupted
        while filenames:
            filename = filenames[0]
            try:
                line = [str(counter), str(filename.name)]
                image = uf.File2Data(filename)
                if image is None:
                    line.extend(["Error reading"])
                else:
                    oIOSImage = uf.InProgress(iipf.cIOSImage, image, filename.name)
                    if (
                        oIOSImage.oCWStrings is not None
                        and oIOSImage.oCWStrings.err is None
                    ):
                        line.extend(
                            [
                                uf.cn(
                                    vn(oIOSImage.oCWStrings.dCWStrings, b"CW_VERSION")
                                ).decode(),
                                uf.cn(
                                    vn(oIOSImage.oCWStrings.dCWStrings, b"CW_FAMILY")
                                ).decode(),
                            ]
                        )
                    else:
                        line.extend([uf.cn(None), uf.cn(None)])
                    line.extend(
                        [
                            str(len(image)),
                            f"{Entropy(image):.2f}",
                            str(oIOSImage.err),
                            str(oIOSImage.oELF.err),
                            str(oIOSImage.oELF.countSections),
                            str(uf.cn(oIOSImage.oELF.stringTableIndex)),
                            str(uf.cn(oIOSImage.checksumCompressed, "0x{:08X}")),
                            str(
                                oIOSImage.checksumCompressed is not None
                                and oIOSImage.checksumCompressed
                                == oIOSImage.calculatedChecksumCompressed
                            ),
                            str(uf.cn(oIOSImage.checksumUncompressed, "0x{:08X}")),
                            str(
                                oIOSImage.checksumUncompressed is not None
                                and oIOSImage.checksumUncompressed
                                == oIOSImage.calculatedChecksumUncompressed
                            ),
                            uf.cn(oIOSImage.imageUncompressedName),
                            uf.cn(oIOSImage.embeddedMD5),
                        ]
                    )
                    if arguments["md5db"]:
                        md5hash = hashlib.md5(image).hexdigest()
                        filenameCSV, filenameDB, filedateDB = oMD5Database.Find(md5hash)
                        line.extend(
                            [
                                md5hash,
                                uf.cn(filenameCSV),
                                uf.cn(filenameDB),
                                uf.cn(filedateDB),
                            ]
                        )
                strLine = ",".join(line)
                print(strLine)
                if log_file is not None:
                    log_file.write(strLine + "\n")
                counter += 1
                filenames = filenames[1:]
            except KeyboardInterrupt:
                print("KeyboardInterrupt")
                PickleData([filenames, countFilenames, counter])
                interrupted = True
                return
            except:
                traceback.print_exc()
                PickleData([filenames, countFilenames, counter])
                interrupted = True
                return

    if arguments["log"] is not None:
        log_mode = "a" if arguments["resume"] else "w"
        with open(arguments["log"], log_mode, encoding="utf-8") as log_file:
            run_scan(log_file)
    else:
        run_scan()
    if not interrupted:
        print("")
        print(f"{(counter - 1):d} file(s) scanned.")
