#!/usr/bin/env python
# coding: utf-8
import hashlib
import logging
import os
import re

import keystoneauth1
import neutronclient.neutron.client
import novaclient.client

import datetime
import time

import yaml
from keystoneclient.auth.identity import v2
from novaclient.exceptions import NotFound

from xcloud import utils

log = logging.getLogger(__name__)
DIRNAME = os.path.dirname(__file__)

clients = {}

OS_SIZES = {'tiny': 1, 'small': 2, 'medium': 3, 'large': 4, 'xlarge': 5}


class Cloud:
    def __init__(self, options):
        self._options = options

        self._novaClient, self._neutronClient = Cloud.construct_nova_client(options)

        self._flavors = None
        self._images = None

        self._image = None
        self._pool_ips = None

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

    def find_servers(self, role):

        ret = []
        log.info('locating servers...')
        servers = utils.retry(self._novaClient.servers.list)

        for server in servers:
            if 'role' in server.metadata:
                if server.metadata['role'] == role:
                    ret.append(self.fix_server_attributes(server))
        return ret

    def delete_server(self, server):
        log.info('deleting server %s...' % server.name)
        utils.retry(self._novaClient.servers.delete, server.id)

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

        # get all ports
        ports = utils.retry(self._neutronClient.list_ports)

        # associate floating ip to server
        log.info('adding floating ip %s to server %s...' %
                 (floating_ip, server.id))
        utils.retry(self._novaClient.servers.add_floating_ip, server.id, floating_ip)

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

        utils.retry(self._neutronClient.update_port, port['id'],
                    {'port': {'allowed_address_pairs': address_pairs}})

    def get_floating_ips(self, ip_pool):
        if self._pool_ips:
            return self._pool_ips

        all_ips = utils.retry(self._novaClient.floating_ips.list)

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

            log.info('creating a new floating IP (%s)...', ip_source)
            ip = utils.retry(self._novaClient.floating_ips.create, ip_source)
            return ip.ip.encode('ascii', 'ignore')

    def format_server_naming(self, server_naming):
        hash = hashlib.sha1()
        hash.update(str(time.time()))
        md5_hash = hash.hexdigest()[:5]
        server_naming['shortname'] = self._options['shortname']

        return server_naming['format'].format(code=md5_hash, **server_naming)

    def get_userdata(self, server_info):
        cloud_init = utils.render(self._options.get('cloud_init', ''), server=server_info,
                                  options=self._options)

        return """#!/usr/bin/env bash
SERVER_COUNT={is_first}

(

set -ae;
{cloud_init}

)
if [ $? -eq 0 ]; then
    echo "done" > /tmp/cloud_init
else
    echo "error" > /tmp/cloud_init
fi
        """.format(cloud_init=cloud_init,
                   is_first=server_info.get('server_count', 0))

    def wait_for_cloudinit(self, server, user='centos'):

        options = self._options

        server_ip = self.get_server_fixed_ip(server, raise_error=True)
        timeout = utils.tdelta(options.get('cloudinit_timeout', '20m'))
        warning_timeout = utils.tdelta(options.get('cloudinit_warning', '5m'))
        start = datetime.datetime.now()
        log.info('waiting for cloud-init (%s)...' % server_ip)

        while True:
            try:
                log.debug('Checking...')

                diff = datetime.datetime.now() - start
                stdout = (diff > warning_timeout)

                rc = utils.ssh(server_ip,
                               """
    STATE=$(cat /tmp/cloud_init)
    if [ "$STATE" == "done" ]; then
      exit 0
    else
      exit 2
    fi
    """,
                               user=user,
                               stdout=stdout,
                               raise_error=False)
                if rc == 0:
                    diff = datetime.datetime.now() - start
                    log.info('done [%s]!' % str(diff))
                    break
                elif rc == 1:
                    raise Exception('cloud_init failed')
                else:
                    diff = datetime.datetime.now() - start
                    if diff > timeout:
                        raise Exception(
                            'error: Timeout while waiting for ssh. Please increase ssh_timeout if more time is needed.')
                    log.info('not done yet (rc=%s)!' % rc)

            except Exception, e:
                diff = datetime.datetime.now() - start
                if diff > timeout:
                    raise Exception(
                        'error: Timeout while waiting for ssh. Please increase ssh_timeout if more time is needed.')
                log.info('no ssh yet!')
            time.sleep(20)

    def delete_all(self):
        servers = utils.retry(self._novaClient.servers.list)
        for item in servers:
            print 'deleting server %s...' % item.name
            utils.retry(self._novaClient.servers.delete, item.id)
        server_groups = utils.retry(self._novaClient.server_groups.list)
        for item in server_groups:
            print 'deleting servergroup %s...' % item.name
            utils.retry(self._novaClient.server_groups.delete, item.id)

    def create_or_get_server_group(self, server_info):
        options = self._options
        if 'server_group' in options:
            server_group = options['server_group']
            group_name = '%s-%s' % (server_info['availability_zone'], options['name'])
            policy = server_group['policy']

            # Search for a group
            server_groups = utils.retry(self._novaClient.server_groups.list)
            for server_group in server_groups:
                if group_name == server_group.name:
                    if policy in server_group.policies:
                        return server_group
                    else:
                        raise RuntimeError('Server group "%s" already exists with '
                                           'different policies: %s' %
                                           (group_name, server_group.policies))

            log.info('creating server group %s [%s]...', group_name, policy)

            server_group = utils.retry(self._novaClient.server_groups.create, name=group_name,
                                       policies=[policy])
            return server_group
        return None

    def read_files(self, server_info):
        options = self._options
        networking = options.get('networking', {})
        files = {}

        cloud = {
            'cloud': {
                'floating_ips': [server_info['floating_ip']],
                'virtual_ips': self.get_virtual_ips(networking),
                'availability_zone': server_info['availability_zone'],
            }
        }

        cloud_yaml = yaml.dump(cloud, default_flow_style=False)
        files['/opt/puppetlabs/facter/facts.d/cloud.yaml'] = cloud_yaml

        for f in options.get('files', []):
            if not (server_info.get('server_count', 0) == 0 and f.get('skip_on_first', False)):
                if 'source' in f:
                    source = os.path.expandvars(f['source'])
                    with open(source, 'r') as fhd:
                        files[f['name']] = fhd.read()
                elif 'content' in f:
                    files[f['name']] = f['content']
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
            az = getattr(node, 'OS-EXT-AZ:availability_zone')

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
            time.sleep(10)

    def finalize_server(self, server, is_first=False):
        fixed_ip = self.get_server_fixed_ip(server)
        log.info('finalizing %s (%s) server...', server.name, fixed_ip)
        self.wait_for_cloudinit(server)
        self.wait_for_cloudready(server, is_first=is_first)

    def create_server(self, server_info):

        options = self._options

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

        os_meta = {
            'login_groups': ','.join(security.get('login_groups', [])),
            'login_users': ','.join(security.get('login_users', [])),
            'sudo_users': ','.join(security.get('sudo_users', [])),
            'sudo_groups': ','.join(security.get('sudo_groups', [])),
            'role': options['name'],
            'floating_ip': server_info['floating_ip'],
        }

        if not options.get('spacewalk', True):
            os_meta['disable_spacewalk'] = 'true'

        if not options.get('pbis', True):
            os_meta['disable_pbis'] = 'true'

        files = self.read_files(server_info)
        availability_zone = server_info['availability_zone']

        flavors = self.get_flavors()
        log.info('creating server %s on %s...', server_name, availability_zone)
        server = utils.retry(self._novaClient.servers.create,
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

        return self.get_server(server.id)

    def get_flavors(self):
        if self._flavors:
            return self._flavors

        log.info('loading flavors...')
        flavors = {}
        for flavor in utils.retry(self._novaClient.flavors.list):
            flavors[flavor.name] = flavor.id
        self._flavors = flavors
        return flavors

    def get_server(self, server_id):
        return utils.retry(self._get_server, server_id)

    def _get_server(self, server_id):
        try:
            server = self._novaClient.servers.get(server_id)

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
        images = utils.retry(self._novaClient.images.list, detailed=True)

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
            self.execute_scripts(update_scripts, server, False)

    def scale(self, args):
        if args.watch is True:
            while True:
                self._scale(args)
                time.sleep(5)
        else:
            self._scale(args)

    @staticmethod
    def get_server_age(server):
        create_time = time.strptime(server.created,
                                    "%Y-%m-%dT%H:%M:%SZ")
        create_dt = datetime.datetime.fromtimestamp(
            time.mktime(create_time))
        return datetime.datetime.utcnow() - create_dt

    def _scale(self, args):

        options = self._options

        scaling = options.get('scaling', {})
        strategy = scaling.get('strategy', 'series')

        new_servers = []
        deleted_servers = []
        servers = utils.retry(self.find_servers, options['name'])

        replicas = self.determine_replicas(args, len(servers))
        fip_info = None

        rebuild = args.rebuild
        original_servers = []
        if rebuild:
            original_servers = [x for x in servers if Cloud.get_server_age(x) > args.max_age]

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
                self.wait_for_new_servers(new_servers)

                new_servers = []
                deleted_servers = []

                if rebuild:
                    if len(original_servers) > 0:
                        self.delete_server(original_servers[0])
                        self.wait_for_deleted([original_servers[0]])
                        del original_servers[0]
                        continue
                break
            else:
                if fip_info is None:
                    fip_info = self.get_floating_ip_pool()

                is_first = (len(servers) == 0)
                server_info = {
                    'availability_zone': self.find_availability_zone(servers),
                    'servers': servers,
                    'floating_ip': self.get_floating_ip(*fip_info),
                    'peers': self.get_peers(servers),
                    'is_first': is_first,
                    'server_count': len(servers),
                }

                server = self.create_server(server_info)

                if strategy == 'series' or (strategy == 'one-parallel' and is_first):
                    self.wait_for_new_servers([server], is_first=is_first)
                else:
                    new_servers.append(server)
                servers.append(server)

        log.info('done')

    def wait_for_new_servers(self, new_servers, is_first=False):

        servers = []
        while len(new_servers) > 0:
            idx = 0
            log.info('waiting for new servers (%s remaining)...' % len(new_servers))
            while idx < len(new_servers):
                new_server = new_servers[idx]
                server = self.get_server(new_server.id)
                if server.status == 'ACTIVE':
                    server = self.wait_for_fixedip(server)
                    self.bind_ip(server, server.metadata['floating_ip'])

                    servers.append(server)
                    new_servers.remove(new_server)
                else:
                    idx += 1

            if len(new_servers) == 0:
                break

            time.sleep(10)

        for server in servers:
            self.finalize_server(server, is_first=is_first)
            log.info('server %s is now active...', server.name)

    def wait_for_deleted(self, deleted_servers):
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

    def get_peers(self, servers):
        peers = []
        for server in servers:
            fixed_ip = self.get_server_fixed_ip(server)
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

    def wait_for_cloudready(self, server, is_first=False):
        options = self._options

        if 'cloud_ready' in options:
            log.info('running cloud ready scripts...')
            self.execute_scripts(options['cloud_ready'], server, is_first=is_first)

    def execute_scripts(self, scripts, server, is_first=False):
        fixed_ip = self.get_server_fixed_ip(server)
        if isinstance(scripts, str):
            scripts = [{
                'shell': scripts
            }]
        for script in scripts:
            if script.get('skip_on_first', False) and is_first:
                continue

            if 'shell' in script:
                rc = os.system('FIXED_IP=%s\n%s' % (fixed_ip, script['shell']))
                if rc != 0:
                    raise RuntimeError('shell script failed (rc=%s)' % rc)
            if 'ssh' in script:
                stdout = script.get('stdout', False)
                sudo = script.get('sudo', False)
                rc = utils.ssh(fixed_ip, script['ssh'], user='centos', stdout=stdout, sudo=sudo)
                if rc != 0:
                    raise RuntimeError('ssh script failed (rc=%s)' % rc)

    def get_virtual_ips(self, networking):
        if 'virtual_ips' in networking:
            if isinstance(networking['virtual_ips'], str):
                return networking['virtual_ip_groups'][networking['virtual_ips']]
            return networking['virtual_ips']
        return []
