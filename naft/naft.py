#!/usr/bin/env python3

__description__ = "Network Appliance Forensic Toolkit"
__version__ = "v1.0.0"
__original_author__ = "Didier Stevens"
__current_authors__ = "@digitalsleuth and @G-K7"

import naft.modules.gfe as gfe
import naft.modules.icd as icd
import naft.modules.ii as ii
import naft.modules.impf as impf
import naft.modules.iipf as iipf
import naft.modules.pfef as pfef
import naft.modules.uf as uf
import argparse
import sys

def missing_req(requirement):
    req_error = {
        'core': 'Please provide a core dump using the -c/--core argument',
        'ios': 'Please provide an IOS file using the --ios argument',
        'iomem': 'Please provide an IOMEM file using the --iomem argument',
        'pcap' : 'Please provide a PCAP filename to output using --pcap',
        'list' : 'Please use the --list command to provide at least one file to search',
        'output' : 'This command requires dumping files to disk, please use the -o/--output argument'
    }
    print(req_error[requirement])
    return

def main():
    parser = argparse.ArgumentParser(description=__description__ + ' ' + str(__version__), add_help=False)
    generalGroup = parser.add_argument_group('General Options')
    generalGroup.add_argument('-v', '--verbose', action='store_true', default=False, help='Increase output verbosity')
    generalGroup.add_argument('-c', '--core', required=False, metavar='COREDUMP')

    coreGroup = parser.add_argument_group('---------------------------------------------------------\nIOS Core Dump - requires -c/--core')
    coreGroup.add_argument('--regions', action='store_true', required=False, help='List Regions')
    coreGroup.add_argument('--heap', action='store_true', required=False, help='List Heaps')
    coreGroup.add_argument('--cwstrings', action='store_true', required=False, help='Print CW_ strings')
    coreGroup.add_argument('--history', action='store_true', required=False, help='Print history')
    coreGroup.add_argument('--proc', action='store_true', required=False, help='Print Processes')
    coreGroup.add_argument('--check', action='store_true', required=False, help='Compare text in dump to IOS - requires --ios')
    coreGroup.add_argument('--integrity', action='store_true', required=False, help='Check integrity of core dump')
    coreGroup.add_argument('--events', action='store_true', required=False, help='Print events')

    coreGroup.add_argument('--ios', required=False, metavar='IOS-BIN')
    coreGroup.add_argument('-o', '--output', required=False, metavar='DIR', default=None, help='Dumps the regions, heap blocks, or IOS to DIR')
    coreGroup.add_argument('-a', '--raw', action='store_true', default=False, help='search in the whole file for CW_ strings, requires --cwstrings')
    coreGroup.add_argument('-d', '--dump', action='store_true', default=False, help='dump data, requires --heap')
    coreGroup.add_argument('-D', '--dumpraw', action='store_true', default=False, help='dump raw data, requires --heap')
    coreGroup.add_argument('-s', '--strings', action='store_true', default=False, help='dump strings in data, requires --heap')
    coreGroup.add_argument('-m', '--minimum', type=int, default=0, help='minimum count number of strings, requires --heap')
    coreGroup.add_argument('-g', '--grep', default='', metavar='STRING', help='grep strings, requires --heap')
    coreGroup.add_argument('-r', '--resolve', action='store_true', default=False, help='resolve names, requires --heap')
    coreGroup.add_argument('-f', '--filter', default='', help='filter for given name, requires --heap or --proc')
    coreGroup.add_argument('-S', '--stats', action='store_true', default=False, help='Print process structure statistics, requires --proc')

    networkGroup = parser.add_argument_group('---------------------------------------------------------\nGeneric Frame Extraction - requires at least -c/--core')
    networkGroup.add_argument('--frames', action='store_true', help='extract frames from coredump and iomem, requires -c/--core, --iomem, --pcap')
    networkGroup.add_argument('--packets', action='store_true', help='extract packets from coredump and/or iomem, requires --list <file1> <file2>, and --pcap')
    networkGroup.add_argument('--list', nargs='+', help='list of files to extract packets from, use --list <file1> <file2>')
    networkGroup.add_argument('--iomem', required=False, metavar='IOMEM')
    networkGroup.add_argument('--pcap', required=False, metavar='PCAP')

    networkGroup.add_argument('--duplicates', action='store_true', default=False, help='include duplicates')
    networkGroup.add_argument('-T', '--template', help='filename for the 010 Editor template to generate')
    networkGroup.add_argument('-p', '--options', action='store_true', default=False, help='Search for IPv4 headers with options')
    networkGroup.add_argument('-t', '--ouitxt', help='ouitxt filename to filter MAC addresses with unknown ID')
    networkGroup.add_argument('-b', '--buffer', action='store_true', default=False, help='Buffer file in 100MB blocks with 1MB overlap')
    networkGroup.add_argument('-B', '--buffersize', type=int, default=100, help='Size of buffer in MB (default 100MB)')
    networkGroup.add_argument('-O', '--bufferoverlapsize', default=1, help='Size of buffer overlap in MB (default 1MB)')

    iosimageGroup = parser.add_argument_group('---------------------------------------------------------\nIOS Image Analysis')
    iosimageGroup.add_argument('-x', '--extract', action='store_true', default=False, help='extract the compressed image, requires --ios and -o/--output')
    iosimageGroup.add_argument('-I', '--idapro', action='store_true', default=False, help='extract the compressed image and patch it for IDA Pro, requires --ios and -o/--output')
    iosimageGroup.add_argument('--scan', action='store_true', default=False, help='scan a set of images, requires --ios')
    iosimageGroup.add_argument('--recurse', action='store_true', default=False, help='recursive scan, requires --ios')
    iosimageGroup.add_argument('-e', '--resume', help='resume an interrupted scan')
    iosimageGroup.add_argument('-M', '--md5db', help='compare md5 hash with provided CSV db')
    iosimageGroup.add_argument('-l', '--log', help='write scan result to log file')

    optionalGroup = parser.add_argument_group('---------------------------------------------------------\nOptional Arguments')
    optionalGroup.add_argument('-h', '--help', action='help', help='show this help message and exit')
    optionalGroup.add_argument('--version', action='version', version='%(prog)s - ' +str(__description__) + ' ' +str(__version__))

    args = parser.parse_args()
    all_args = vars(args)

    if len(sys.argv[1:]) == 0:
        print("Please choose a command from the following:")
        parser.print_usage()
        parser.exit()

    # CoreGroup
    if args.regions:
        if not args.core:
            missing_req('core')
        else:
            icd.IOSRegions(args.core, all_args)

    elif args.heap:
        if not args.core:
            missing_req('core')
        else:
            icd.IOSHeap(args.core, all_args)

    elif args.cwstrings:
        if not args.core:
            missing_req('core')
        else:
            icd.IOSCWStrings(args.core, all_args)

    elif args.history:
        if not args.core:
            missing_req('core')
        else:
            icd.IOSHistory(args.core)

    elif args.proc:
        if not args.core:
            missing_req('core')
        else:
            icd.IOSProcesses(args.core, all_args)

    elif args.check:
        if not args.core:
            missing_req('core')
        elif not args.ios:
            missing_req('ios')
        else:
            icd.IOSCheckText(args.core, args.ios, all_args)

    elif args.integrity:
        if not args.core:
            missing_req('core')
        else:
            icd.IOSIntegrityText(args.core, all_args)

    elif args.events:
        if not args.core:
            missing_req('core')
        else:
            icd.IOSEvents(args.core)

    # NetworkGroup
    elif args.frames:
        if not args.core:
            missing_req('core')
        elif not args.iomem:
            missing_req('iomem')
        else:
            gfe.IOSFrames(args.core, args.iomem, args.pcap, all_args)

    elif args.packets:
        if not args.list:
            missing_req('list')
        elif not args.pcap:
            missing_req('pcap')
        else:
            gfe.ExtractIPPacketsFromFile(args.list, args.pcap, all_args)

    # IOSGroup
    elif args.extract or args.idapro:
        if not args.ios:
            missing_req('ios')
        elif not args.output:
            missing_req('output')
        else:
            ii.CiscoIOSImageFileParser(args.ios, all_args)

    elif args.scan:
        if not args.ios:
            missing_req('ios')
        else:
            ii.CiscoIOSImageFileScanner(args.scan, all_args)

    else:
        print('unrecognized or incomplete command: ', *sys.argv[1:])
        parser.print_usage()
        parser.exit()

if __name__ == '__main__':
    main()
