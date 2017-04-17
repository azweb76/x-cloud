#!/usr/bin/env python
# coding: utf-8
import hashlib
import logging
import os
import sys
import re
import collections
from fnmatch import fnmatch
import multiprocessing as mp
from copy_reg import pickle
from multiprocessing.pool import ApplyResult
from types import MethodType

import keystoneauth1
import neutronclient.neutron.client
import novaclient.client

import datetime
import time

import signal
import yaml
from keystoneclient.auth.identity import v2
from novaclient.exceptions import NotFound

from xcloud import utils

log = logging.getLogger(__name__)
DIRNAME = os.path.dirname(__file__)

clients = {}

OS_SIZES = {'tiny': 1, 'small': 2, 'medium': 3, 'large': 4, 'xlarge': 5}


def _pickle_method(method):
    func_name = method.im_func.__name__
    obj = method.im_self
    cls = method.im_class
    return _unpickle_method, (func_name, obj, cls)


def _unpickle_method(func_name, obj, cls):
    for cls in cls.mro():
        try:
            func = cls.__dict__[func_name]
        except KeyError:
            pass
        else:
            break
    return func.__get__(obj, cls)

pickle(MethodType, _pickle_method, _unpickle_method)

class Cloud(object):
    def __init__(self, options):
        self._options = options

        # self._novaClient, self._neutronClient = Cloud.construct_nova_client(self._options)

        self._flavors = None
        self._images = None

        self._image = None
        self._pool_ips = None
        self._find_servers_cache = {}

        # self._osClient = Cloud.create_openstack_client(options['cloud'])

    @staticmethod
    def create(options):
        return Cloud(options)

    # @staticmethod
    # def create_openstack_client(options):
    #     from openstack import connection, profile
    #     prof = profile.Profile()
    #     prof.set_region(prof.ALL, 'phx3')
    #     conn = connection.Connection(
    #         profile=prof,
    #         auth_url=options['url'],
    #         username=options['username'],
    #         password=options['password'],
    #         project_name=options['project_name'],
    #         user_domain_id='default',
    #         project_domain_id='default'
    #     )
    #     return conn

    @staticmethod
    def construct_nova_client(options):

        timeout = options.get('timeout', 600)
        auth = v2.Password(auth_url=options['auth_url'],
                           username=options['username'],
                           password=options['password'],
                           tenant_name=options['project_name'])
        nova_client = novaclient.client.Client(
            options['openstack_api_version'],
            session=keystoneauth1.session.Session(auth=auth, timeout=timeout),
            timeout=timeout, )
        neutron_client = neutronclient.neutron.client.Client(
            '{}.0'.format(options['openstack_api_version']),
            session=keystoneauth1.session.Session(auth=auth, timeout=timeout))

        return nova_client, neutron_client

    def find_servers(self, role, cachable=False):
        """
        Used to locate servers by role.

        role: role value stored in the role metadata field
        """

        ns_role = '%s/%s' % (self._options.get('namespace', 'default'), role)
        if cachable:
            if ns_role in self._find_servers_cache:
                return self._find_servers_cache[ns_role]

        novaClient, neutronclient = Cloud.construct_nova_client(self._options)
        ret = []

        log.info('locating servers (%s)...', ns_role)
        servers = utils.retry(novaClient.servers.list)

        for server in servers:
            if 'role' in server.metadata:
                if server.metadata['role'] == ns_role:
                    ret.append(self.get_server_info(server))

        if cachable:
            self._find_servers_cache[ns_role] = ret

        return ret

    def _delete_server(self, server_id):
        try:
            novaClient, neutronClient = Cloud.construct_nova_client(self._options)
            novaClient.servers.delete(server_id)
        except NotFound:
            pass

    def pull_server(self, server_info):
        options = self._options

        log.info('pulling server %s...' % server_info.name)
        scripts = options.get('scripts', {}).get('cloud_pull', None)
        self.execute_scripts(scripts, server_info)

    def delete_server(self, server_info, skip_delete_scripts=False):
        options = self._options

        self.pull_server(server_info)

        if not skip_delete_scripts:
            delete_scripts = options.get('scripts', {}).get('cloud_delete', None)
            self.execute_scripts(delete_scripts, server_info)

        log.info('deleting server %s...' % server_info.name)
        novaClient, neutronClient = Cloud.construct_nova_client(self._options)
        utils.retry(novaClient.servers.delete, server_info.id)

    def get_server_fixed_ip_by_id(self, server_id):
        server = self.get_server(server_id)
        return self.get_server_fixed_ip(server, raise_error=True)

    def get_server_fixed_ip(self, server, raise_error=False):
        for server_addr in server.addresses:
            for addr_zone in server.addresses[server_addr]:
                if addr_zone['OS-EXT-IPS:type'] == 'fixed':
                    return addr_zone['addr']
        if raise_error:
            raise RuntimeError('could not find fixed IP')
        return None

    def bind_ip(self, server, floating_ip):
        options = self._options.get('networking', {})

        novaClient, neutronClient = Cloud.construct_nova_client(self._options)

        # get all ports
        ports = utils.retry(neutronClient.list_ports)

        # associate floating ip to server
        log.info('adding floating ip %s to server %s...' %
                 (floating_ip, server.id))
        utils.retry(novaClient.servers.add_floating_ip, server.id, floating_ip)

        fixed_ip = None

        # find fixed IP
        for network_label, address_list in server.networks.items():
            fixed_ip = address_list[0]

        # find fixed IP port ID
        for port in ports['ports']:
            if port['fixed_ips'][0]['ip_address'] == fixed_ip:
                break

        address_pairs = [{'ip_address': floating_ip}]
        virtual_ips = self.get_virtual_ips(options)

        if virtual_ips and len(virtual_ips) > 0:
            log.info(
                'binding floating ip %s (and %s other(s)) to port %s...' %
                (floating_ip, len(virtual_ips), port['id']))
            address_pairs += [{'ip_address': x}
                              for x in virtual_ips]
        else:
            log.info('binding floating ip %s to port %s...' %
                     (floating_ip, port['id']))

        utils.retry(neutronClient.update_port, port['id'],
                    {'port': {'allowed_address_pairs': address_pairs}})

    def get_floating_ips(self, ip_pool):
        if self._pool_ips:
            return self._pool_ips

        novaClient, neutronClient = Cloud.construct_nova_client(self._options)
        all_ips = utils.retry(novaClient.floating_ips.list)

        pool_ips = filter(
            lambda x: x.instance_id is None and x.pool == ip_pool,
            all_ips)
        self._pool_ips = pool_ips = map(lambda x: x.ip.encode('ascii', 'ignore'), pool_ips)
        return pool_ips

    def get_floating_ip_pool(self):
        networking = self._options.get('networking', {})
        if 'floating_ips' in networking:
            floating_ips = networking['floating_ips']
            ip_pools = networking.get('ip_pools', {})
            ip_pool = ip_pools[floating_ips]

            if isinstance(ip_pool, str):
                return self.get_floating_ips(ip_pool), ip_pool, ip_pools
            else:
                return self.get_floating_ips(ip_pool['source']), ip_pool, ip_pools

        return None

    def get_floating_ip(self, pool_ips, ip_pool, ip_pools):

        if pool_ips is not None:
            if 'fixed' in ip_pool:
                for fixed_ip in ip_pool['fixed']:
                    if fixed_ip in pool_ips:
                        ip_pool['fixed'].remove(fixed_ip)
                        return fixed_ip
                raise RuntimeError('No fixed floating_ips are available.')

            if len(pool_ips) > 0:
                for ip in pool_ips:
                    in_pool = False
                    for ip_pool_name in ip_pools:
                        ip_pool = ip_pools[ip_pool_name]
                        if 'fixed' in ip_pool:
                            if ip in ip_pool['fixed']:
                                in_pool = True
                    if not in_pool:
                        pool_ips.remove(ip)
                        return ip

            if isinstance(ip_pool, str):
                ip_source = ip_pool
            else:
                ip_source = ip_pool['source']

            novaClient, neutronClient = Cloud.construct_nova_client(self._options)
            log.info('creating a new floating IP (%s)...', ip_source)
            ip = utils.retry(novaClient.floating_ips.create, ip_source)
            return ip.ip.encode('ascii', 'ignore')

    def format_server_naming(self, server_naming):
        hash = hashlib.sha1()
        hash.update(str(time.time()))
        md5_hash = hash.hexdigest()[:5]
        server_naming['shortname'] = self._options['shortname']

        return server_naming['format'].format(code=md5_hash, **server_naming)

    def get_userdata(self, server_info):
        cloud_init = utils.render(self._options.get('cloud_init', ''), server=server_info,
                                  env=self._options['env'], options=self._options, cloud=self)

        xcloud_config = self.get_cloud_config(server_info)
        script = """#!/usr/bin/env bash
SERVER_COUNT={server_count}

(

set -ae;
{xcloud_config}
{cloud_init}

)
if [ $? -eq 0 ]; then
    echo "done" > /tmp/cloud_init
else
    echo "error" > /tmp/cloud_init
fi
        """.format(cloud_init=cloud_init,
                   xcloud_config=xcloud_config,
                   server_count=server_info.get('server_count', 0))

        return script

    def wait_for_cloudinit(self, server, user='centos'):
        fixed_ip = self.get_server_fixed_ip(server, raise_error=True)
        self.wait_for_ssh(fixed_ip, """
    STATE=$(cat /tmp/cloud_init)
    if [ "$STATE" == "done" ]; then
      exit 0
    elif [ "$STATE" == "error" ]; then
      exit 1
    else
      exit 2
    fi
    """, user=user, command_name='cloudinit')

    def wait_for_ssh(self, server_ip, ssh, command_name='ssh', user='centos'):

        options = self._options

        timeout = utils.tdelta(options.get('%s_timeout' % command_name, '20m'))
        warning_timeout = utils.tdelta(options.get('%s_warning' % command_name, '5m'))
        start = datetime.datetime.now()
        log.info('waiting for %s (%s)...' % (command_name, server_ip))

        while True:
            try:
                log.debug('checking...')

                diff = datetime.datetime.now() - start
                stdout = (diff > warning_timeout)

                rc = utils.ssh(server_ip, ssh,
                               user=user,
                               stdout=stdout,
                               raise_error=False)
                if rc == 0:
                    diff = datetime.datetime.now() - start
                    log.info('done [%s]!' % str(diff))
                    break
                elif rc == 1:
                    raise Exception('%s failed' % command_name)

                log.info('not done yet (rc=%s)!' % rc)

            except KeyboardInterrupt:
                exit(1)

            diff = datetime.datetime.now() - start
            if diff > timeout:
                raise Exception(
                    'error: Timeout while waiting for ssh. Please increase ssh_timeout if more time is needed.')
            time.sleep(20)

    def delete_all(self):
        novaClient, neutronClient = Cloud.construct_nova_client(self._options)
        servers = utils.retry(novaClient.servers.list)
        for item in servers:
            print 'deleting server %s...' % item.name
            utils.retry(novaClient.servers.delete, item.id)
        server_groups = utils.retry(novaClient.server_groups.list)
        for item in server_groups:
            print 'deleting servergroup %s...' % item.name
            utils.retry(novaClient.server_groups.delete, item.id)

    def create_or_get_server_group(self, server_info):
        options = self._options
        if 'server_group' in options:
            server_group = options['server_group']
            group_name = '%s-%s' % (server_info['availability_zone'], options['name'])
            policy = server_group['policy']

            # Search for a group
            novaClient, neutronClient = Cloud.construct_nova_client(self._options)
            server_groups = utils.retry(novaClient.server_groups.list)
            for server_group in server_groups:
                if group_name == server_group.name:
                    if policy in server_group.policies:
                        return server_group
                    else:
                        raise RuntimeError('Server group "%s" already exists with '
                                           'different policies: %s' %
                                           (group_name, server_group.policies))

            log.info('creating server group %s [%s]...', group_name, policy)

            server_group = utils.retry(novaClient.server_groups.create, name=group_name,
                                       policies=[policy])
            return server_group
        return None

    def read_files(self, server_info):
        options = self._options
        networking = options.get('networking', {})
        files = {}

        floating_ips = []
        floating_ip = server_info.get('floating_ip', None)
        if floating_ip:
            floating_ips.append(floating_ip)
        cloud = {
            'cloud_floating_ip': floating_ip,
            'cloud_virtual_ips': self.get_virtual_ips(networking),
            'cloud_availability_zone': server_info['availability_zone'],
        }

        cloud_yaml = yaml.dump(cloud, default_flow_style=False)
        files['/opt/puppetlabs/facter/facts.d/cloud.yaml'] = cloud_yaml

        env = options['env']
        for f in options.get('files', []):
            if not (server_info.get('server_count', 0) == 0 and f.get('skip_on_first', False)):
                if 'source' in f:
                    source = f['source'].format(**env)
                    with open(source, 'r') as fhd:
                        files[f['name']] = fhd.read()
                elif 'content' in f:
                    files[f['name']] = f['content']
                elif 'template' in f:
                    files[f['name']] = utils.render(f['template'], cloud=self, server=server_info, env=env)
                elif 'env' in f:
                    files[f['name']] = env[f['env']]
                else:
                    raise RuntimeError('missing source or content in file')

        return files

    # def wait_for_attributes(self, node, attribute_name):
    #     try:
    #         getattr(node, attribute_name)
    #         return node
    #     except:
    #         return self.get_server(node.id)

    def find_availability_zone(self, servers):
        options = self._options

        preferred_zone = None
        preferred_pct = 0

        avail_zones = options['availability_zones']
        zones_total = 0.0
        total_weight = 0.0

        zones_available_count = 0

        for avail_zone in avail_zones:
            if not avail_zone.get('exceeded', False):
                zones_available_count += 1

                weight = avail_zone.get('weight', 1)
                avail_zone['weight'] = weight
                avail_zone['allocations'] = 0

                total_weight += weight

        if zones_available_count / float(len(avail_zones)) <= 0.5:
            raise Exception('Not enough available zones to provision server.')

        for node in servers:
            az = node['availability_zone']
            #az = getattr(node, 'OS-EXT-AZ:availability_zone')

            avail_zone = [x for x in avail_zones if x['name'] == az]
            if len(avail_zone) > 0:
                avail_zone[0]['allocations'] += 1
                zones_total += 1

        for avail_zone in avail_zones:

            zone_pct = 0
            if zones_total > 0 and total_weight > 0:
                zone_pct = (avail_zone['allocations'] / zones_total) - \
                           (avail_zone['weight'] / float(total_weight))

            if preferred_zone is None or zone_pct < preferred_pct:
                preferred_zone = avail_zone
                if zones_total > 0 and total_weight > 0:
                    preferred_pct = (preferred_zone[
                                         'allocations'] / zones_total) - (preferred_zone['weight'] /
                                                                          float(total_weight))
        if not preferred_zone:
            raise Exception('error: unable to find zone')
        else:
            return preferred_zone['name']

    def wait_for_fixedip(self, server):
        while True:
            fixed_ip = self.get_server_fixed_ip(server)
            if fixed_ip is not None:
                return server
            server = self.get_server(server.id)

            log.info('waiting for fixed ip...')
            time.sleep(3)

    def finalize_server(self, server, is_first=False):
        fixed_ip = self.get_server_fixed_ip(server)
        log.info('finalizing %s (%s) server...', server.name, fixed_ip)
        self.wait_for_cloudinit(server)
        self.wait_for_cloudready(server, is_first=is_first)

    def create_server(self, server_info):

        options = self._options

        novaClient, neutronClient = Cloud.construct_nova_client(self._options)
        image_id = self.get_image().id
        server_name = self.format_server_naming(options.get('server_naming', {}))
        user_data = self.get_userdata(server_info)

        security = options.get('security', {})

        if 'login_users' not in security:
            security['login_users'] = []
        if 'login_groups' not in security:
            security['login_groups'] = []

        server_group = self.create_or_get_server_group(server_info)
        scheduler_hints = dict(group=server_group.id) if server_group else None

        ns_role = '%s/%s' % (self._options.get('namespace', 'default'), options['name'])
        os_meta = {
            'login_groups': ','.join(security.get('login_groups', [])),
            'login_users': ','.join(security.get('login_users', [])),
            'sudo_users': ','.join(security.get('sudo_users', [])),
            'sudo_groups': ','.join(security.get('sudo_groups', [])),
            'role': ns_role,
            'floating_ip': server_info.get('floating_ip','') or '',
        }

        if not options.get('spacewalk', True):
            os_meta['disable_spacewalk'] = 'true'

        if not options.get('pbis', True):
            os_meta['disable_pbis'] = 'true'

        files = self.read_files(server_info)
        availability_zone = server_info['availability_zone']

        flavors = self.get_flavors()
        log.info('creating server %s on %s...', server_name, availability_zone)
        server = utils.retry(novaClient.servers.create,
                             server_name,
                             image_id,
                             flavors[options.get('instance_size', 'm1.small')],
                             meta=os_meta,
                             userdata=user_data,
                             files=files,
                             availability_zone=availability_zone,
                             key_name=security['ssh_key_name'],
                             security_groups=security.get('security_groups', ['default']),
                             scheduler_hints=scheduler_hints)

        server = self.wait_for_fixedip(server)
        return self.get_server_info(server)

    def get_flavors(self):
        if self._flavors:
            return self._flavors

        log.info('loading flavors...')
        flavors = {}
        nova_client, neutron_client = Cloud.construct_nova_client(self._options)
        for flavor in utils.retry(nova_client.flavors.list):
            flavors[flavor.name] = flavor.id
        self._flavors = flavors
        return flavors

    def get_server(self, server_id):
        return utils.retry(self._get_server, server_id)

    def _get_server(self, server_id):
        try:
            novaClient, neutronClient = Cloud.construct_nova_client(self._options)
            server = novaClient.servers.get(server_id)

            # delay loads data
            getattr(server, 'OS-EXT-AZ:availability_zone')
            return server
        except NotFound:
            return None
        except:
            raise

    def get_image(self):
        if self._image:
            return self._image

        image_expr = self._options.get('image', '^centos7-base')
        log.info('finding latest image (image=%s)...', image_expr)
        novaClient, neutronClient = Cloud.construct_nova_client(self._options)

        if 'image_id' in self._options:
            self._image = novaClient.images.get(self._options['image_id'])
            return self._image

        images = utils.retry(novaClient.images.list, detailed=True)

        newest_image = None
        newest_created = None

        for image in images:
            if re.match(image_expr, image.name):
                if image.metadata.get('recommended', 'false') == 'true':
                    created = time.strptime(image.created, "%Y-%m-%dT%H:%M:%SZ")
                    if newest_image is None or created > newest_created:
                        newest_image = image
                        newest_created = created

        self._image = newest_image
        return newest_image

    def fix_server_attributes(self, server):
        setattr(server, 'fqdn', '%s.%s' % (server.name, self._options['instance_fqdn_suffix']))
        setattr(server, 'fixed_ip', self.get_server_fixed_ip(server))
        return server

    def update_servers(self, args):
        options = self._options

        servers = utils.retry(self.find_servers, options['name'])

        update_scripts = options.get('cloud_update', [])
        for server in servers:
            log.info('updating %s...', server.name)
            self.execute_scripts(update_scripts, self.get_server_info(server), is_first=False)

    def scale(self, args):
        if args.watch is True:
            while True:
                try:
                    self._scale(args)
                except KeyboardInterrupt:
                    exit(1)
                except:
                    log.warning('failed to scale, retrying in 5s')
                time.sleep(5)
        else:
            self._scale(args)

    @staticmethod
    def get_server_age(server):
        return datetime.datetime.utcnow() - server.created

    def reboot_servers(self, args):
        servers = self.find_servers(args.name)

        for server in servers:
            server.reboot()
            self.wait_for_ssh(server, 'hostname')
            self.validate_server(server)

    def _scale(self, args):

        options = self._options

        scaling = options.get('scaling', {})
        strategy = scaling.get('strategy', 'series')

        new_servers = []
        deleted_servers = []
        servers = utils.retry(self.find_servers, options['name'])

        self.delete_errored_servers(servers)

        if args.validate:
            self.validate_servers(servers)

        replicas = self.determine_replicas(args, len(servers))
        fip_info = None

        rebuild = args.rebuild
        original_servers = []
        if rebuild:
            for x in servers:
                age = Cloud.get_server_age(x)
                if args.min_age <= age <= args.max_age:
                    if fnmatch(x.name, args.server_name):
                        original_servers.append(x)

            if args.force:
                log.info('deleting servers (force rebuild)...')
                while len(original_servers) > 0:
                    self.delete_server(original_servers[0])
                    deleted_servers.append(original_servers[0])
                    servers.remove(original_servers[0])
                    del original_servers[0]
                self.wait_for_deleted(deleted_servers)

        while True:
            if len(servers) > replicas:
                deleted_servers.append(servers[0])
                self.delete_server(servers[0])
                if len(original_servers):
                    if servers[0] in original_servers:
                        original_servers.remove(servers[0])
                del servers[0]
            elif len(servers) == replicas:
                self.wait_for_deleted(deleted_servers)
                self.wait_for_new_servers(new_servers, servers)

                new_servers = []
                deleted_servers = []

                if rebuild:
                    if len(original_servers) > 0:
                        while len(original_servers) > 0:
                            self.delete_server(original_servers[0])
                            deleted_servers.append(original_servers[0])
                            servers.remove(original_servers[0])
                            del original_servers[0]
                            if not args.force:
                                break
                        self.wait_for_deleted(deleted_servers)
                        continue
                break
            else:
                if fip_info is None:
                    fip_info = self.get_floating_ip_pool()

                is_first = (len(servers) == 0)
                floating_ip = None
                if fip_info is not None:
                    floating_ip = utils.retry(self.get_floating_ip, *fip_info)

                server_info = {
                    'availability_zone': self.find_availability_zone(servers),
                    'servers': servers,
                    'floating_ip': floating_ip,
                    'peers': self.get_peers(servers),
                    'is_first': is_first,
                    'server_count': len(servers),
                }

                server = self.create_server(server_info)
                servers.append(server)

                if strategy == 'series' or (strategy == 'one-parallel' and is_first):
                    self.wait_for_new_servers([server], servers, is_first=is_first)
                else:
                    new_servers.append(server)

        log.info('done')

    def get_cloud_config(self, server_info):
        sysctl = {'vm.swappiness':1}

        networks = {}
        commands = []

        virtual_ips = server_info.get('virtual_ips', [])
        if len(virtual_ips) > 0:
            vip_idx = 0
            for vip in virtual_ips:
                networks['lo:'+vip_idx] = {
                    'DEVICE': "lo:"+vip_idx,
                    'BOOTPROTO': "none",
                    'ONBOOT': "yes",
                    'TYPE': "Ethernet",
                    'USERCTL': "no",
                    'PEERDNS': "no",
                    'PEERNTP': "no",
                    'IPADDR': vip,
                    'NETMASK': "255.255.255.255",
                    'ARP': "no",
                }
                vip_idx += 1
            sysctl['net.ipv4.conf.all.arp_announce'] = 2
            sysctl['net.ipv4.conf.default.arp_announce'] = 2
            sysctl['net.ipv4.conf.all.arp_ignore'] = 1
            sysctl['net.ipv4.conf.default.arp_ignore'] = 1
            sysctl['net.ipv4.conf.all.rp_filter'] = 0
            sysctl['net.ipv4.conf.default.rp_filter'] = 0

        commands.append(utils.cat_file('/etc/sysctl.d/xcloud.conf', sysctl))
        commands.append('/usr/sbin/sysctl -p /etc/sysctl.d/xcloud.conf')

        if 'floating_ip' in server_info:
            networks['tunl0'] = {
                'DEVICE': "tunl0",
                'BOOTPROTO': "none",
                'ONBOOT': "yes",
                'TYPE': "Ethernet",
                'USERCTL': "no",
                'PEERDNS': "no",
                'PEERNTP': "no",
                'IPADDR': server_info['floating_ip'],
                'NETMASK': "255.255.255.255",
            }
            commands.append(utils.cat_file('/etc/modprobe.d/tunl.conf', 'alias tunl0 ipip'))

        for net_name in networks:
            net_file = '/etc/sysconfig/network-scripts/ifcfg-%s' % net_name
            commands.append(utils.cat_file(net_file, networks[net_name]))
            commands.append('/usr/sbin/ifup %s' % net_name)

        return '\n'.join(commands)

    def validate_server(self, server_info, is_first=False):
        options = self._options
        scripts = options.get('scripts', {})
        if 'cloud_validate' in scripts:
            log.info('validating server %s...', server_info.name)
            self.execute_scripts(scripts['cloud_validate'], server_info, is_first=is_first)

    def wait_for_new_servers(self, new_servers, servers, is_first=False):

        finalize_servers = []
        while len(new_servers) > 0:
            idx = 0
            log.info('waiting for new servers (%s remaining)...' % len(new_servers))
            while idx < len(new_servers):
                new_server = new_servers[idx]
                server = self.get_server(new_server.id)
                if server.status == 'ACTIVE':
                    server = self.wait_for_fixedip(server)
                    floating_ip = server.metadata.get('floating_ip', None)
                    if floating_ip:
                        self.bind_ip(server, floating_ip)

                    finalize_servers.append(server)
                    new_servers.remove(new_server)
                elif server.status == 'ERROR':
                    log.info('server failed provisioning (%s)', server.fault['message'])
                    log.info('server %s failed, deleting...' % server.name)
                    self.delete_server(server)
                    new_servers.remove(new_server)
                    servers.remove(new_server)
                else:
                    idx += 1

            if len(new_servers) == 0:
                break

            time.sleep(10)

        for server in finalize_servers:
            self.finalize_server(server, is_first=is_first)

        for server in finalize_servers:
            self.validate_server(server, is_first=is_first)
            log.info('server %s is now active...', server.name)

    def wait_for_deleted(self, deleted_servers):
        options = self._options
        retry_timeout = utils.tdelta(options.get('delete_retry_timeout', '1m'))
        start = datetime.datetime.now()
        while len(deleted_servers) > 0:
            idx = 0
            log.info('waiting for deleted servers...')
            while idx < len(deleted_servers):
                deleted_server = deleted_servers[idx]

                server = self.get_server(deleted_server.id)
                if server is None:
                    deleted_servers.remove(deleted_server)

                if server is not None:
                    idx += 1

            if len(deleted_servers) == 0:
                break

            time.sleep(10)

            diff = datetime.datetime.now() - start
            if diff > retry_timeout:
                log.warn('retrying server deletes...')
                for server in deleted_servers:
                    utils.retry(self.delete_server, server, skip_delete_scripts=True)
                start = datetime.datetime.now()

    def get_peers(self, servers):
        peers = []
        for server in servers:
            fixed_ip = server.get('fixed_ip', None)
            if fixed_ip is not None:
                peers.append(fixed_ip)
        return peers

    def determine_replicas(self, args, current_size):
        if args.replicas is not None:
            return args.replicas

        scaling = self._options.get('scaling', {})
        if current_size == 0:
            return scaling.get('initial_size', 1)
        return current_size

    def wait_for_cloudready(self, server_info, is_first=False):
        options = self._options

        if 'cloud_ready' in options:
            log.info('running cloud ready scripts...')
            self.execute_scripts(options['cloud_ready'], server_info, is_first=is_first)

    def get_server_info(self, server):
        create_time = time.strptime(server.created,
                                    "%Y-%m-%dT%H:%M:%SZ")
        create_dt = datetime.datetime.fromtimestamp(
            time.mktime(create_time))

        return utils.AttributeDict({
            'id': server.id,
            'fqdn': '%s.%s' % (server.name, self._options['instance_fqdn_suffix']),
            'fixed_ip': self.get_server_fixed_ip(server),
            'metadata': utils.AttributeDict(server.metadata),
            'name': server.name,
            'created': create_dt,
            'flavor': server.flavor,
            'status': server.status,
            'availability_zone': getattr(server, 'OS-EXT-AZ:availability_zone'),
        })

    def execute_script(self, script, server_info, target_servers):
        if target_servers is None:
            if 'target' in script:
                servers = [x for x in self.find_servers(script['target'])]
            else:
                servers = [server_info]
        else:
            servers = target_servers

        server_idx = 0
        while True:

            target_server = servers[server_idx]

            target_server['target'] = server_info
            try:
                utils.retry(self.execute_shell, script, target_server)
                utils.retry(self.execute_ssh, script, target_server)
                break
            except KeyboardInterrupt:
                exit(0)
            except:
                server_idx += 1
                if server_idx >= len(servers):
                    raise
                else:
                    log.exception('failed to run script on %s, trying next' % target_server['fqdn'])

    def execute_ssh(self, script, server_info):

        fixed_ip = server_info['fixed_ip']
        fqdn = server_info['fqdn']

        options = self._options
        if 'ssh' in script:
            stdout = script.get('stdout', False)
            sudo = script.get('sudo', False)
            cmd = utils.render(script['ssh'], server=server_info, env=options['env'], cloud=self)
            exit_on_error = script.get('exit_on_error', True)

            log.info('executing ssh command on %s...' % fqdn)
            rc = utils.ssh(fixed_ip, cmd, user='centos',
                           stdout=stdout, sudo=sudo, raise_error=False, exit_on_error=exit_on_error)
            if rc != 0:
                if rc == 255 and script.get('wait_for_reboot', False):
                    self.wait_for_ssh(fixed_ip, 'hostname', 'ssh_reboot')
                else:
                    raise RuntimeError('ssh script failed (rc=%s) on %s' % (rc, fqdn))

    def execute_shell(self, script, server_info):
        options = self._options
        if 'shell' in script:
            rc = os.system(utils.render(script['shell'], server=server_info, env=options['env']))
            if rc != 0:
                raise RuntimeError('shell script failed (rc=%s)' % rc)

    def execute_scripts(self, scripts, server, target_servers=None, is_first=False):
        if scripts is not None:
            if isinstance(scripts, str):
                scripts = [{
                    'shell': scripts
                }]
            for script in scripts:
                if script.get('skip_on_first', False) and is_first:
                    continue
                self.execute_script(script, server, target_servers)
        return {'success': True}

    def get_virtual_ips(self, networking):
        if 'virtual_ips' in networking:
            if isinstance(networking['virtual_ips'], str):
                return networking['virtual_ip_groups'][networking['virtual_ips']]
            return networking['virtual_ips']
        return []

    def delete_errored_servers(self, servers):
        deleted_servers = []
        log.info('deleting any errored servers...')
        for server in servers:
            if server.status == 'ERROR':
                self.delete_server(server, skip_delete_scripts=True)
                deleted_servers.append(server)
        self.wait_for_deleted(deleted_servers)

    def _run_scripts(self, state):
        scripts, server, target_servers, is_first = state
        result = self.execute_scripts(scripts, server, target_servers=target_servers, is_first=is_first)
        log.info('done: %s', server['fqdn'])
        return result

    def run_scripts(self, args):
        options = self._options
        original_servers = self.find_servers(options['name'])

        servers = []
        for x in original_servers:
            age = Cloud.get_server_age(x)
            if args.min_age <= age <= args.max_age:
                if fnmatch(x.name, args.server_name):
                    servers.append(x)

        if args.script == '-':
            all_scripts = {
                args.script: [{'ssh': sys.stdin.read(), 'sudo': args.sudo, 'stdout':args.stdout}]
            }
        else:
            all_scripts = options.get('scripts', {})

        if args.script in all_scripts:
            scripts = all_scripts[args.script]

            if 'target' in scripts:
                targets = self.find_servers(scripts['target'])
                target_servers = [x for x in targets]
            else:
                target_servers = None

            pool = mp.Pool(processes=args.threads)
            p = pool.map_async(self._run_scripts, [(scripts, x, target_servers, False,) for x in
                                                   servers])
            try:
                print p.get(0xFFFF)
            except KeyboardInterrupt:
                print "Caught KeyboardInterrupt, terminating workers"
                pool.terminate()
                pool.join()
                raise
        else:
            log.info('script %s was not found in %s', args.script, options['name'])

    def validate_servers(self, servers):
        for server in servers:
            self.validate_server(server, False)
