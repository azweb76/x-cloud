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
        options = {}
        config_file = os.path.expanduser('~/.xcloud')
        if os.path.exists(config_file):
            with open(config_file, 'r') as fhd:
                options = yaml.load(fhd)

        parser = argparse.ArgumentParser(description='Provision servers in openstack.')

        parser.add_argument(
            '-l',
            '--log-level',
            dest='log_level',
            default='INFO',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            help='optional. Set the log level.')

        # parser.add_argument('-c', '--config', default='~/.xcloud', required=True, help='x-cloud config file used to '
        #                     'store openstack information')
        parser.add_argument('-u', '--username', default=os.environ.get('XCLOUD_USERNAME', None),
                            help='username to access openstack')
        parser.add_argument('-p', '--password', default=os.environ.get('XCLOUD_PASSWORD', None),
                            help='password to access openstack')
        parser.add_argument('-f', '--file', default=None, required=True, help='provision manifest file')

        subparsers = parser.add_subparsers(help='actions')

        parser_a = subparsers.add_parser('scale', help='resize servers')
        parser_a.add_argument('-w', '--watch', default=False, action='store_true', help='watch the servers')
        parser_a.add_argument('-r', '--replicas', default=None, type=int, help='number of servers to scale to')
        parser_a.add_argument('--rebuild', default=False, action='store_true', help='rebuild the servers one-by-one')
        parser_a.add_argument('--max-age', default='1d', type=utils.tdelta, help='max age to rebuild servers')
        parser_a.add_argument('-n', '--name', default='*', type=str, help='name of cluster')
        parser_a.set_defaults(func=scale_cli)

        parser_a = subparsers.add_parser('update', help='update servers')
        parser_a.add_argument('-n', '--name', default='*', type=str, help='name of cluster')
        parser_a.set_defaults(func=update_cli)

        parser_a = subparsers.add_parser('delete-all', help='delete all servers')
        parser_a.add_argument('-n', '--name', default='*', type=str, help='name of cluster')
        parser_a.set_defaults(func=delete_all_cli)

        parser_a = subparsers.add_parser('list', help='list all servers')
        parser_a.add_argument('-n', '--name', default='*', type=str, help='name of cluster')
        parser_a.set_defaults(func=list_cli)

        args = parser.parse_args()
        logging.getLogger('requests').setLevel(logging.ERROR)
        fmt = "[%(relativeCreated)-8d] %(levelname)s %(module)s: %(message)s"
        logging.basicConfig(level=getattr(logging, args.log_level), format=fmt)

        args.func(args)
    except KeyboardInterrupt:
        exit(0)


def delete_all_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.name):
            cloud = cloud.Cloud.create(options)
            cloud.delete_all()


def scale_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.name):
            cloud = Cloud.create(options)
            cloud.scale(args)


def update_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.name):
            cloud = Cloud.create(options)
            cloud.update_servers(args)


def list_cli(args):
    all_options = CloudOptions.create_from_file(args.file, args)
    for options in all_options:
        option_name = options['name']
        if fnmatch(option_name, args.name):
            cloud = Cloud.create(options)
            servers = cloud.find_servers(option_name)

            print 'CLUSTER: %s' % option_name
            print ''
            print '  %s %s %s' % ('fqdn'.ljust(30), 'ip'.ljust(15), 'floater'.ljust(15))
            print '  %s %s %s' % ('-' * 30, '-' * 15, '-' * 30)
            for server in servers:
                print '  %s %s %s' % (server.fqdn.ljust(30), server.fixed_ip.ljust(15), server.metadata['floating_ip'].ljust(15))
            print ''


if __name__ == '__main__':
    main()
