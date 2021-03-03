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
        'core': 'Please provide a core dump using the --coredump argument.',
        'binary': 'Please provide an IOS binary using the --binary argument.',
        'iomem': 'Please provide an IOMEM file using the --iomem argument.',
        'pcap' : 'Please provide a PCAP output filename using the --pcap argument.',
        'list' : 'Please use the --list command to provide at least one file to search.',
        'output' : 'This command requires dumping files to disk, please use the -o/--output argument.',
        'coremem': 'Please provide core dump and IOMEM files using --coredump & --iomem arguments.'
    }
    print(req_error[requirement])
    return

def main():
    main_parser = argparse.ArgumentParser(
        description='Network Appliance Forensics Toolkit',
        usage='naft.py [subcommand] [options] [core/iomem/binary]',
        epilog="Use -h on these subcommands to print the available options."
    )

    subparsers = main_parser.add_subparsers(title='subcommands', metavar='', prog='naft.py')

    core_parser = subparsers.add_parser('core', help='core dump artifacts')
    core = core_parser.add_argument_group('functions')
    group = core.add_mutually_exclusive_group(required=True)
    group.add_argument('--regions', action='store_true', help='list regions, [-o]')
    group.add_argument('--cwstrings', action='store_true', help='print CW_ strings, [-a]')
    group.add_argument('--heap', action='store_true', help='list heaps, [-d] [-D] [-s] [-m] [-g] [-r] [-f] [-o] [-v]')
    group.add_argument('--history', action='store_true', help='print history')
    group.add_argument('--events', action='store_true', help='print events')
    group.add_argument('--processes', action='store_true', help='print processes, [-f] [-d] [-t]')
    group.add_argument('--check', action='store_true', help='compare text in dump to IOS bin, requires --binary')
    group.add_argument('--integrity', action='store_true', help='check integrity of core dump')
    core_parser.add_argument('coredump', help='router core dump file')
    core_parser.add_argument('-a', '--raw', action='store_true', default=False, help='search in the whole file for CW_ strings')
    core_parser.add_argument('-d', '--dump', action='store_true', default=False, help='dump data')
    core_parser.add_argument('-D', '--dumpraw', action='store_true', default=False, help='dump raw data')
    core_parser.add_argument('-s', '--strings', action='store_true', default=False, help='dump strings in data')
    core_parser.add_argument('-m', '--minimum', type=int, default=0, help='minimum count number of strings',metavar='COUNT')
    core_parser.add_argument('-g', '--grep', default='', help='grep strings', metavar='STRING')
    core_parser.add_argument('-r', '--resolve', action='store_true', default=False, help='resolve names')
    core_parser.add_argument('-f', '--filter', default='', help='filter for given name', metavar='NAME')
    core_parser.add_argument('-o', '--output', help='write the regions or heap blocks to path', metavar='PATH')
    core_parser.add_argument('--binary', help='router binary file', metavar='FILE')
    core_parser.add_argument('-v', '--verbose', action='store_true', default=False, help='increase output verbosity')
    core_parser.add_argument('-t', '--stats', action='store_true', default=False, help='print process structure statistics')


    network_parser = subparsers.add_parser('network', help='generic frame extraction')
    network = network_parser.add_argument_group('functions')
    network_group = network.add_mutually_exclusive_group(required=True)
    network_group.add_argument('--frames', help='extract frames and store them in a .pcap file, requires --coredump & --iomem', metavar='PCAP')
    network_group.add_argument('--packets', help='extract packets and store them in a .pcap file, requires --list', metavar='PCAP')
    frames = network_parser.add_argument_group('frames options')
    frames.add_argument('--coredump', help='router core dump file', metavar='FILE')
    frames.add_argument('--iomem', help='router iomem dump file', metavar='FILE')
    frames.add_argument('-v', '--verbose', action='store_true', default=False, help='increase output verbosity')
    packets = network_parser.add_argument_group('packets options')
    packets.add_argument('--list', nargs='+', metavar='FILE', help='list of files to extract packets from, use --list <file1> <file2>')
    packets.add_argument('-d', '--duplicates', action='store_true', default=False, help='include duplicates')
    packets.add_argument('-p', '--options', action='store_true', default=False, help='search for IPv4 headers with options')
    packets.add_argument('-t', '--ouitxt', help='ouitxt filename to filter MAC addresses with unknown ID')
    packets.add_argument('-b', '--buffer', action='store_true', default=False, help='buffer file in 100MB blocks with 1MB overlap')
    packets.add_argument('-B', '--buffersize', type=int, default=100, help='size of buffer in MB (default 100MB)')
    packets.add_argument('-O', '--bufferoverlapsize', type=int, default=1, help='size of buffer overlap in MB (default 1MB)')


    image_parser = subparsers.add_parser('image', help='IOS image analysis')
    image = image_parser.add_argument_group('functions')
    image_group = image.add_mutually_exclusive_group(required=True)
    image_group.add_argument('--extract', help='extract the compressed image to path, requires --binary [-m] [-v]', metavar='PATH')
    image_group.add_argument('--idapro', help='extract the compressed image to path and patch it for IDA Pro, requires --binary [-m] [-v]', metavar='PATH')
    image_group.add_argument('--scan', action='store_true', default=False, help='scan a set of images, binary requires a wildcard [-R] [-r] [-m] [-l]')
    image_parser.add_argument('-m', '--md5db', help='compare md5 hash with provided CSV db', metavar='CSV')
    image_parser.add_argument('binary', help='router binary file, use wildcard for --scan')
    image_parser.add_argument('-R', '--recurse', action='store_true', default=False, help='recursive scan')
    image_parser.add_argument('-r', '--resume', action='store_true', default=False, help='resume an interrupted scan')
    image_parser.add_argument('-l', '--log', help='write scan result to log file', metavar='FILE')
    image_parser.add_argument('-v', '--verbose', action='store_true', default=False, help='increase output verbosity')


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
            icd.IOSHeap(args.coredump, all_args)
        elif args.history:
            icd.IOSHistory(args.coredump)
        elif args.events:
            icd.IOSEvents(args.coredump)
        elif args.processes:
            icd.IOSProcesses(args.coredump, all_args)
        elif args.check:
            if not args.binary:
                missing_req('binary')
            else:
                icd.IOSCheckText(args.coredump, args.binary, all_args)
        elif args.integrity:
            icd.IOSIntegrityText(args.coredump, all_args)

    if sys.argv[1] == 'network':
        if args.frames is not None:
            if not args.coredump or not args.iomem:
                missing_req('coremem')
            else:
                gfe.IOSFrames(args.coredump, args.iomem, args.frames, all_args)
        elif args.packets is not None:
            if not args.list:
                missing_req('list')
            else:
                gfe.ExtractIPPacketsFromFile(args.list, args.packets, all_args)

    if sys.argv[1] == 'image':
        if args.extract is not None or args.idapro is not None:
            ii.CiscoIOSImageFileParser(args.binary, all_args)
        elif args.scan:
            ii.CiscoIOSImageFileScanner(args.binary, all_args)

if __name__ == '__main__':
    main()