import getpass
import yaml
import os
import logging

#from xcrypto import xcrypto
from xcloud import utils

log = logging.getLogger(__name__)


class YamlLoader(yaml.Loader):
    def __init__(self, stream):
        self._root = os.path.split(stream.name)[0]

        super(YamlLoader, self).__init__(stream)

    def include(self, node):
        return self._include(node, self._root)

    def sysfile(self, node):
        return self._include(node, os.environ.get('SYS_PATH', self._root))

    def syspath(self, node):
        base_path = os.environ.get('SYS_PATH', self._root)
        return os.path.join(base_path, self.construct_scalar(node))

    def _include(self, node, base_path):
        filename = os.path.join(base_path, self.construct_scalar(node))

        with open(filename, 'r') as fhd:
            y = fhd.read()

        return y

    def load(self, node):
        filename = os.path.join(self._root, self.construct_scalar(node))

        with open(filename, 'r') as fhd:
            y = yaml.load(fhd, YamlLoader)

        return y

    def resolve_path(self, node):
        filename = os.path.join(self._root, self.construct_scalar(node))
        return filename.encode('ascii', 'ignore')


#YamlLoader.add_constructor('!encrypted', YamlLoader.encrypted)
YamlLoader.add_constructor('!file', YamlLoader.include)
YamlLoader.add_constructor('!sysfile', YamlLoader.sysfile)
YamlLoader.add_constructor('!syspath', YamlLoader.syspath)
YamlLoader.add_constructor('!yaml', YamlLoader.load)
YamlLoader.add_constructor('!resolve', YamlLoader.resolve_path)


class CloudOptions(dict):

    @staticmethod
    def create_from_file(filename, args):

        all_options = []

        base_path = os.path.dirname(filename)
        with open(filename, 'r') as fhd:
            region = yaml.load(fhd, YamlLoader)

        defaults = region.get('defaults', {})
        clusters = region.get('clusters', [])
        all_files = region.get('files', [])
        all_cloud_init = region.get('cloud_init', [])

        env = region.get('env', {})

        for idx in range(0, len(clusters)):
            cluster = clusters[idx]
            if isinstance(cluster, str):
                p = utils.resolve_path(cluster, base_path)
                with open(p, 'r') as fhd:
                    clusters[idx] = yaml.load(fhd)
            else:
                d = {}
                if 'extend' in cluster:
                    p = utils.resolve_path(cluster['extend'], base_path)
                    del cluster['extend']

                    with open(p, 'r') as fhd:
                        d = yaml.load(fhd, YamlLoader)

                clusters[idx] = utils.extend(d, cluster)

        region_scripts = region.get('scripts', {})
        for cluster in clusters:
            cluster = utils.extend(defaults, cluster)

            cluster['files'] = all_files + cluster.get('files', [])
            cluster['cloud_init'] = all_cloud_init + cluster.get('cloud_init', [])
            cluster['scripts'] = dict(region_scripts, **cluster.get('scripts', {}))
            cluster['env'] = dict(env, **cluster.get('env', {}))

            options = CloudOptions(cluster)

            if args.username:
                options['username'] = args.username

            if args.password:
                options['password'] = args.password

            all_options.append(options)

        return all_options

