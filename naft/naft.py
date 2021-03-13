#!/usr/bin/env python3

__description__ = 'Network Appliance Forensic Toolkit'
__version__ = 'v1.0.0b1'
__original_author__ = 'Didier Stevens'
__current_authors__ = '@digitalsleuth and @G-K7'
__date__ = '2021/03/09'

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
        'core': 'Please provide a core dump using the --coredump argument.',
        'bin': 'Please provide an IOS bin file using the --bin argument.',
        'iomem': 'Please provide an IOMEM file using the --iomem argument.',
        'pcap' : 'Please provide a PCAP output filename using the --pcap argument.',
        'files' : 'Please use the --files command to provide at least one file to search.',
        'output' : 'This command requires dumping files to disk, please use the -o/--output argument.',
        'coremem': 'Please provide core dump and IOMEM files using --coredump & --iomem arguments.',
        'strings': 'The -g/--grep command requires -s/--strings, please retry your command with -s/--strings.'
    }
    print(req_error[requirement])
    return

def main():
    main_parser = argparse.ArgumentParser(
        description=__description__ + ' ' + str(__version__),
        usage='naft [category] [function] [optional/required arguments]',
        epilog="Use -h on each category to view all available options."
    )

    subparsers = main_parser.add_subparsers(title='categories', metavar='Select one of the three following categories to begin analysis', prog='naft')

    core_parser = subparsers.add_parser('core', help='Core Dump')
    core = core_parser.add_argument_group('functions')
    core_group = core.add_mutually_exclusive_group(required=True)
    core_group.add_argument('--regions', action='store_true', help='List regions: [-o]')
    core_group.add_argument('--cwstrings', action='store_true', help='Print CW_ strings: [-a]')
    core_group.add_argument('--heap', action='store_true', help='List heaps: [-d] [-D] [-s] [-m] [-g] [-r] [-f] [-o] [-v]')
    core_group.add_argument('--history', action='store_true', help='Print history')
    core_group.add_argument('--events', action='store_true', help='Print events')
    core_group.add_argument('--processes', action='store_true', help='Print processes: [-f] [-d] [-S]')
    core_group.add_argument('--check', action='store_true', help='Compare text in dump to IOS bin, requires --bin')
    core_group.add_argument('--integrity', action='store_true', help='Check integrity of core dump')
    core_parser.add_argument('coredump', help='Core dump file')
    core_parser.add_argument('-a', '--raw', action='store_true', default=False, help='Search the whole core dump for CW_ strings')
    core_parser.add_argument('-d', '--dump', action='store_true', default=False, help='Dump data')
    core_parser.add_argument('-D', '--dumpraw', action='store_true', default=False, help='Dump raw data')
    core_parser.add_argument('-s', '--strings', action='store_true', default=False, help='Dump strings in data')
    core_parser.add_argument('-m', '--minimum', type=int, default=0, help='Minimum count number of strings', metavar='COUNT')
    core_parser.add_argument('-g', '--grep', default='', help='Grep for strings', metavar='STRING')
    core_parser.add_argument('-r', '--resolve', action='store_true', default=False, help='Resolve names for processes')
    core_parser.add_argument('-f', '--filter', default='', help='Filter for a given name', metavar='NAME')
    core_parser.add_argument('-o', '--output', help='Output the regions or heap blocks to path', metavar='PATH')
    core_parser.add_argument('--bin', help='IOS bin file', metavar='FILE')
    core_parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Increase output verbosity')
    core_parser.add_argument('-S', '--stats', action='store_true', default=False, help='Print process structure statistics')


    network_parser = subparsers.add_parser('network', help='Generic Frame and Packet Extraction')
    network = network_parser.add_argument_group('functions')
    network_group = network.add_mutually_exclusive_group(required=True)
    network_group.add_argument('--frames', help='Extract frames and store them in a .pcap file, requires --coredump & --iomem', metavar='PCAP')
    network_group.add_argument('--packets', help='Extract packets and store them in a .pcap file, requires --files', metavar='PCAP')
    frames = network_parser.add_argument_group('Frames options')
    frames.add_argument('--coredump', help='Core dump file', metavar='FILE')
    frames.add_argument('--iomem', help='iomem dump file', metavar='FILE')
    frames.add_argument('-v', '--verbose', action='store_true', default=False, help='Increase output verbosity')
    packets = network_parser.add_argument_group('Packets options')
    packets.add_argument('--files', nargs='+', metavar='FILE', help='List of files to extract packets from, use --files <file1> <file2>')
    packets.add_argument('-d', '--duplicates', action='store_true', default=False, help='Include duplicates')
    packets.add_argument('-p', '--options', action='store_true', default=False, help='Search for IPv4 headers with options')
    packets.add_argument('-t', '--ouitxt', help='File containing OUI\'s to filter for MAC addresses')
    packets.add_argument('-b', '--buffer', action='store_true', default=False, help='Buffer the file in 100MB blocks with 1MB overlap')
    packets.add_argument('-B', '--buffersize', type=int, default=100, help='Explicitly set size of buffer in MB (default 100MB)')
    packets.add_argument('-O', '--bufferoverlapsize', type=int, default=1, help='Explicitly set size of buffer overlap in MB (default 1MB)')


    image_parser = subparsers.add_parser('image', help='IOS Image Analysis')
    image = image_parser.add_argument_group('functions')
    image_group = image.add_mutually_exclusive_group(required=True)
    image_group.add_argument('--info', action='store_true', default=False, help='Scan defined image and output metadata, requires --bin')
    image_group.add_argument('--extract', help='Extract the compressed image to path, requires --bin: [-m] [-v]', metavar='PATH')
    image_group.add_argument('--ida', help='Extract the compressed image to path and patch it for IDA Pro, requires --bin: [-m] [-v]', metavar='PATH')
    image_group.add_argument('--scan', metavar='DIR', help='Find and scan all images within DIR: [-R] [-r] [-m] [-l]')
    image_parser.add_argument('--bin', help='IOS bin file', metavar='FILE')
    image_parser.add_argument('-m', '--md5db', help='Compare MD5 hash with provided CSV formatted db', metavar='CSV')
    image_parser.add_argument('-R', '--recurse', action='store_true', default=False, help='Recursively search sub-directories for images')
    image_parser.add_argument('-r', '--resume', help='Resume an interrupted scan from Pickle file', metavar='PKL')
    image_parser.add_argument('-l', '--log', help='Write scan result to log file', metavar='FILE')
    image_parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Increase output verbosity')


    args = main_parser.parse_args()
    all_args = vars(args)
    if len(all_args) == 0:
        main_parser.print_help()
        main_parser.exit()

    if sys.argv[1] == 'core':
        if args.regions:
            icd.IOSRegions(args.coredump, all_args)
        elif args.cwstrings:
            icd.IOSCWStrings(args.coredump, all_args)
        elif args.heap:
            if args.grep and not args.strings:
                missing_req('strings')
            else:
                icd.IOSHeap(args.coredump, all_args)
        elif args.history:
            icd.IOSHistory(args.coredump)
        elif args.events:
            icd.IOSEvents(args.coredump)
        elif args.processes:
            icd.IOSProcesses(args.coredump, all_args)
        elif args.check:
            if not args.bin:
                missing_req('bin')
            else:
                icd.IOSCheckText(args.coredump, args.bin, all_args)
        elif args.integrity:
            icd.IOSIntegrityText(args.coredump, all_args)

    if sys.argv[1] == 'network':
        if args.frames:
            if not args.coredump or not args.iomem:
                missing_req('coremem')
            else:
                gfe.IOSFrames(args.coredump, args.iomem, args.frames, all_args)
        elif args.packets:
            if not args.files:
                missing_req('files')
            else:
                gfe.ExtractIPPacketsFromFile(args.files, args.packets, all_args)

    if sys.argv[1] == 'image':
        if args.extract or args.ida or args.info:
            if not args.bin:
                missing_req('bin')
            else:
                ii.CiscoIOSImageFileParser(args.bin, all_args)
        if args.scan:
            ii.CiscoIOSImageFileScanner(args.scan, all_args)

if __name__ == '__main__':
    main()
