#!/usr/bin/env python
# coding: utf-8

import argparse
import logging
import os
from fnmatch import fnmatch

import yaml

import utils

from xcloud.cloud import Cloud
from xcloud.cloudoptions import CloudOptions

_log = logging.getLogger(__name__)


def main():
    try:
        # options = {}
        # config_file = os.path.expanduser('~/.xcloud')
        # if os.path.exists(config_file):
        #     with open(config_file, 'r') as fhd:
        #         options = yaml.load(fhd)

        parser = argparse.ArgumentParser(description='Provision servers in openstack.')

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
        parser.add_argument('-f', '--file', default=None, required=True, help='provision manifest file')
        parser.add_argument('--crypto-key', default=os.environ.get('XCRYPTO_KEY', None), required=False,
                            help='key used to decrypt !encrypted tags in config')

        subparsers = parser.add_subparsers(help='actions')

        parser_a = subparsers.add_parser('scale', help='resize servers')
        parser_a.add_argument('-w', '--watch', default=False, action='store_true', help='watch the servers')
        parser_a.add_argument('-r', '--replicas', default=None, type=int, help='number of servers to scale to')
        parser_a.add_argument('--rebuild', default=False, action='store_true', help='rebuild the servers')
        parser_a.add_argument('-p', '--parallel', default=False, action='store_true', help='rebuild all the servers in parallel')
        parser_a.add_argument('--min-age', default='0s', type=utils.tdelta, help='minimum age to rebuild servers')
        parser_a.add_argument('--max-age', default='9999d', type=utils.tdelta, help='max age to rebuild servers')
        parser_a.add_argument('--server-name', default='*', type=str, help='name of servers to rebuild')
        parser_a.add_argument('--force', action='store_true', help='force and action such as delete')
        parser_a.add_argument('-v', '--validate', default=False, action='store_true',
                              help='validate the servers before scale')
        parser_a.add_argument('-c', '--cluster', default='*', type=str, help='name of cluster')
        parser_a.set_defaults(func=scale_cli)

        parser_a = subparsers.add_parser('update', help='update servers')
        parser_a.add_argument('-c', '--cluster', default='*', type=str, help='name of cluster')
        parser_a.set_defaults(func=update_cli)

        parser_a = subparsers.add_parser('reboot', help='reboot servers')
        parser_a.add_argument('-c', '--cluster', default='*', type=str, help='name of cluster')
        parser_a.set_defaults(func=reboot_cli)

        parser_a = subparsers.add_parser('run', help='run scripts')
        parser_a.add_argument('-c', '--cluster', default='*', type=str, help='name of cluster')
        parser_a.add_argument('--min-age', default='0s', type=utils.tdelta, help='minimum age to rebuild servers')
        parser_a.add_argument('--max-age', default='9999d', type=utils.tdelta, help='max age to rebuild servers')
        parser_a.add_argument('--server-name', default='*', type=str, help='name of servers to rebuild')
        parser_a.add_argument('--threads', default=8, type=int, help='name of servers to run in parallel')
        parser_a.add_argument('--stdout', default=False, action='store_true', help='print stdout for stdin script')
        parser_a.add_argument('--sudo', default=False, action='store_true', help='run stdin script as sudo')
        parser_a.add_argument('script', default=None, type=str, help='name of the script to run')
        parser_a.set_defaults(func=run_cli)

        parser_a = subparsers.add_parser('list', help='list all servers')
        parser_a.add_argument('-c', '--cluster', default='*', type=str, help='name of cluster')
        parser_a.set_defaults(func=list_cli)

        args = parser.parse_args()

        logging.getLogger('requests').setLevel(logging.ERROR)
        fmt = "[%(relativeCreated)-8d] %(levelname)s %(module)s: %(message)s"
        logging.basicConfig(level=getattr(logging, args.log_level), format=fmt)

        args.func(args)
    except KeyboardInterrupt:
        exit(0)

def scale_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.cluster):
            cloud = Cloud.create(options)
            cloud.scale(args)


def update_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.cluster):
            cloud = Cloud.create(options)
            cloud.update_servers(args)


def reboot_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.cluster):
            cloud = Cloud.create(options)
            cloud.reboot_servers(args)


def run_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.cluster):
            cloud = Cloud.create(options)
            cloud.run_scripts(args)


def list_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.cluster):
            cloud = Cloud.create(options)
            flavors = {}
            flavors_by_name = cloud.get_flavors()
            for flavor in flavors_by_name:
                flavors[flavors_by_name[flavor]] = flavor
            servers = cloud.find_servers(option_name)

            print 'CLUSTER: %s' % option_name
            print ''
            print '  %s %s %s %s %s' % ('fqdn'.ljust(30), 'ip'.ljust(15), 'floater'.ljust(15), 'created'.ljust(21),
                                     'size'.ljust(20))
            print '  %s %s %s %s %s' % ('-' * 30, '-' * 15, '-' * 15, '-' * 21, '-' * 20)
            for server in servers:
                print '  %s %s %s %s %s' % (server.fqdn.ljust(30), server.fixed_ip.ljust(15),
                                      server.metadata['floating_ip'].ljust(15),
                                            ('%s' % server.created).ljust(21),
                                         flavors[server.flavor['id']].ljust(20))
            print ''


if __name__ == '__main__':
    main()
