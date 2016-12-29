import getpass
import yaml
import os

from xcloud import utils


class CloudOptions(dict):

    @staticmethod
    def create_from_file(filename, args):

        all_options = []

        base_path = os.path.dirname(filename)
        with open(filename, 'r') as fhd:
            region = yaml.load(fhd)

        defaults = region.get('defaults', {})
        clusters = region.get('clusters', [])
        all_files = region.get('files', [])
        all_cloud_init = region.get('cloud_init', '')

        env = region.get('env', {})
        for e in env:
            os.environ[e] = env[e]

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
                        d = yaml.load(fhd)

                clusters[idx] = utils.extend(d, cluster)

        for cluster in clusters:
            cluster = utils.extend(defaults, cluster)

            cluster['files'] = all_files + cluster.get('files', [])
            cluster['cloud_init'] = all_cloud_init + '\n' + cluster.get('cloud_init', '')

            options = CloudOptions(cluster)

            if args.username:
                options['username'] = args.username

            if args.password:
                options['password'] = args.password

            all_options.append(options)

        return all_options

