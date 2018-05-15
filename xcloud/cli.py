#!/usr/bin/env python
# coding: utf-8

import argparse
import logging
import os
from fnmatch import fnmatch

import time
import yaml
import sys

import utils

from xcloud.cloud import Cloud
from xcloud.cloudoptions import CloudOptions

log = logging.getLogger(__name__)


def main():
    try:
        parser = argparse.ArgumentParser(
            description='Provision servers in openstack.')

        parser.add_argument(
            '-l',
            '--log-level',
            dest='log_level',
            default='INFO',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            help='optional. Set the log level.')

        parser.add_argument('-u', '--username', default=os.environ.get('OS_USERNAME', None),
                            help='username to access openstack')
        parser.add_argument('-p', '--password', default=os.environ.get('OS_PASSWORD', None),
                            help='password to access openstack')
        parser.add_argument('-f', '--file', default=None,
                            required=True, help='provision manifest file')
        parser.add_argument('--syspath', default=os.getcwd(),
                            help='path used to resolve syspath, sysfile YAML tags')

        subparsers = parser.add_subparsers(help='actions')

        parser_a = subparsers.add_parser('scale', help='resize servers')
        parser_a.add_argument('-w', '--watch', default=None,
                              type=utils.tdelta, help='interval to watch for changes')
        parser_a.add_argument('-r', '--replicas', default=None,
                              type=int, help='number of servers to scale to')
        parser_a.add_argument('--rebuild', default=False,
                              action='store_true', help='rebuild the servers')
        parser_a.add_argument('--rebuild-all', default=False,
                              action='store_true', help='rebuild all the servers')
        parser_a.add_argument('-p', '--parallel', default=False,
                              action='store_true', help='rebuild all the servers in parallel')
        parser_a.add_argument('--min-age', default='9999d',
                              type=utils.tdelta, help='minimum age to rebuild servers')
        parser_a.add_argument('--max-age', default='9999d',
                              type=utils.tdelta, help='max age to rebuild servers')
        parser_a.add_argument('--servers', default=None,
                              type=str, help='name of servers to rebuild. use - for stdin. delimited by ;,<newline>; supports glob pattern')
        parser_a.add_argument('--force', action='store_true',
                              help='force and action such as delete')
        parser_a.add_argument('-v', '--validate', default=False, action='store_true',
                              help='validate the servers before scale')
        parser_a.add_argument('-c', '--cluster', default='*',
                              type=str, help='name of cluster')
        parser_a.set_defaults(func=scale_cli)

        parser_a = subparsers.add_parser('update', help='update servers')
        parser_a.add_argument('-c', '--cluster', default='*',
                              type=str, help='name of cluster')
        parser_a.add_argument('--network', action='store_true',
                              help='update network config')
        parser_a.set_defaults(func=update_cli)

        parser_a = subparsers.add_parser('reboot', help='reboot servers')
        parser_a.add_argument('-c', '--cluster', default='*',
                              type=str, help='name of cluster')
        parser_a.set_defaults(func=reboot_cli)

        parser_a = subparsers.add_parser('run', help='run scripts')
        parser_a.add_argument('-c', '--cluster', default='*',
                              type=str, help='name of cluster')
        parser_a.add_argument('--min-age', default='0s',
                              type=utils.tdelta, help='minimum age to rebuild servers')
        parser_a.add_argument('--max-age', default='9999d',
                              type=utils.tdelta, help='max age to rebuild servers')
        parser_a.add_argument('--since', default='0d',
                              type=utils.tdelta, help='time since last run')
        parser_a.add_argument('--servers', default='*',
                              type=str, help='name of servers to rebuild. use - for stdin. delimited by ;,<newline>; supports glob pattern')
        parser_a.add_argument('--batch', default=8, type=int,
                              help='number of servers to run in parallel')
        parser_a.add_argument('--stdout', default=False,
                              action='store_true', help='print stdout for stdin script')
        parser_a.add_argument(
            '--sudo', default=False, action='store_true', help='run stdin script as sudo')
        parser_a.add_argument('script', default=None,
                              type=str, help='name of the script to run')
        parser_a.set_defaults(func=run_cli)

        parser_a = subparsers.add_parser('list', help='list all servers')
        parser_a.add_argument('-c', '--cluster', default='*',
                              type=str, help='name of cluster')
        parser_a.add_argument('-s', '--summary', help='summarize the servers',
                              action='store_true')
        parser_a.set_defaults(func=list_cli)

        parser_a = subparsers.add_parser('delete', help='delete servers')
        parser_a.add_argument('-c', '--cluster', default='*',
                              type=str, help='name of cluster')
        parser_a.add_argument('servers', help='servers, delimited by space or newline')
        parser_a.set_defaults(func=delete_cli)

        parser_a = subparsers.add_parser('meta', help='update server metadata')
        parser_a.add_argument('-c', '--cluster', default='*',
                              type=str, help='name of cluster')
        parser_a.add_argument('--filter', help='server name filter')
        parser_a.add_argument('metadata', help='server metadata to update (key=value;key1=value1)')
        parser_a.set_defaults(func=update_metadata)

        parser_a = subparsers.add_parser('setup', help='setup the clusters')
        parser_a.set_defaults(func=setup_cli)

        args = parser.parse_args()

        logging.getLogger('requests').setLevel(logging.ERROR)
        fmt = "[%(relativeCreated)-8d] %(levelname)s %(module)s: %(message)s"
        logging.basicConfig(level=getattr(logging, args.log_level), format=fmt)

        args.func(args)
    except KeyboardInterrupt:
        exit(0)


def scale_cli(args):
    if args.servers and args.servers == '-':
        args.servers = sys.stdin.read().strip('\n ')
    all_options = CloudOptions.create_from_file(args.file, args)
    if args.rebuild_all:
        if not utils.confirm('Are you sure you want to rebuild all?'):
            return
        for options in all_options:
            option_name = options['name']
            if fnmatch(option_name, args.cluster):
                cloud = Cloud.create(options, all_options)
                cloud.delete_all()
    while True:
        try:
            for options in all_options:
                option_name = options['name']
                if fnmatch(option_name, args.cluster):
                    cloud = Cloud.create(options, all_options)
                    cloud.scale(args)
            if args.watch is None:
                break
            time.sleep(args.watch.total_seconds())
        except KeyboardInterrupt:
            raise
        except:
            if args.watch is None:
                raise
            else:
                log.exception(
                    'error while attempting to scale, retrying in 10s')
                time.sleep(10)


def update_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.cluster):
            cloud = Cloud.create(options, all_options)
            cloud.update_servers(args)


def reboot_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.cluster):
            cloud = Cloud.create(options)
            cloud.reboot_servers(args)


def delete_cli(args):
    if args.servers == '-':
        args.servers = sys.stdin.read().strip('\n ')
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.cluster):
            cloud = Cloud.create(options, all_options)
            cloud.delete_servers(args)


def update_metadata(args):
    if args.metadata == '-':
        args.metadata = sys.stdin.read().strip('\n ')
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        metadata = {}
        metadata_str = args.metadata.split(';')
        for x in metadata_str:
            parts = x.split('=')
            metadata[parts[0]] = parts[1]
        if fnmatch(option_name, args.cluster):
            cloud = Cloud.create(options, all_options)
            for server in cloud.find_servers(None, filter=args.filter):
                cloud.update_metadata(server, metadata)
                print 'updated %s metadata' % server.fqdn


def run_cli(args):
    if args.servers == '-':
        args.servers = sys.stdin.read().strip('\n ')
    all_options = CloudOptions.create_from_file(args.file, args)
    try:
        for options in all_options:
            option_name = options['name']
            if fnmatch(option_name, args.cluster):
                cloud = Cloud.create(options, all_options)
                cloud.run_scripts(args)
    except KeyboardInterrupt:
        exit(1)


def setup_cli(args):
    options = CloudOptions.create_from_defaults(args.file, args)
    cloud = Cloud.create(options, {})
    
    cloud.update_security_groups()


def list_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        server_filter = options.get('filter', None)
        if fnmatch(option_name, args.cluster):
            cloud = Cloud.create(options, all_options)
            flavors = {}
            flavors_by_name = cloud.get_flavors()
            for flavor in flavors_by_name:
                flavors[flavors_by_name[flavor]] = flavor
            servers = cloud.find_servers(option_name, filter=server_filter)

            print 'CLUSTER: %s' % option_name
            print ''

            by_size = {}
            if args.summary:
                for server in servers:
                    size = flavors[server.flavor['id']]
                    if size not in by_size:
                        by_size[size] = 1
                    else:
                        by_size[size] += 1
                for size in by_size:
                    print '  %s: %s' % (size, by_size[size])
            else:
                print '  %s %s %s %s %s %s %s %s %s' % ('fqdn'.ljust(30), 'ip'.ljust(15), 'floater'.ljust(15), 'created'.ljust(21),
                                            'size'.ljust(10), 'sensu', 'validated_on'.ljust(26), 'patched_on'.ljust(26), 'tags'.ljust(50))
                print '  %s %s %s %s %s %s %s %s %s' % ('-' * 30, '-' * 15, '-' * 15, '-' * 21, '-' * 10, '-' * 5, 
                    '-' * 26, '-' * 26, '-' * 26)
                for server in servers:
                    info = {}
                    cloud._plugins.on_describe(server, info)
                    print '  %s %s %s %s %s %s %s %s %s' % (server.fqdn.ljust(30), server.fixed_ip.ljust(15),
                                                server.metadata.get(
                                                    'floating_ip', '').ljust(15),
                                                ('%s' % server.created).ljust(21),
                                                flavors[server.flavor['id']].ljust(10),
                                                str(info.get('has_sensu', False)).ljust(5),
                                                str(server.metadata.get('validate_dt', None)).ljust(26),
                                                str(server.metadata.get('patch_dt', None)).ljust(26),
                                                str(server.metadata.get('tags', None)).ljust(50))
            print ''


if __name__ == '__main__':
    main()
