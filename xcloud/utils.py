import collections
import logging
import os
import re
import subprocess
import time
import yaml
import sys
from datetime import timedelta

from jinja2 import DictLoader
from jinja2 import Environment, is_undefined

log = logging.getLogger(__name__)


class AttributeDict(dict):
    def __init__(self, d):
        for x in d:
            self.__setitem__(x, d[x])
            setattr(self, x, d[x])


def tdelta(s):
    keys = ["weeks", "days", "hours", "minutes", "seconds"]
    regex = "".join(["((?P<%s>\d+)%s ?)?" % (k, k[0]) for k in keys])
    kwargs = {}
    for k, v in re.match(regex, s).groupdict(default="0").items():
        kwargs[k] = int(v)
    return timedelta(**kwargs)


def resolve_path(p, base_path):
    if os.path.isabs(p):
        return p
    else:
        return os.path.join(base_path, p)


def read_file(self, p):
    with open(p, 'r') as fhd:
        return fhd.read()


def yaml_filter(value, pretty=False):
    return yaml.dump(value, default_flow_style=not pretty)


def arg_filter(value, arg_name):
    if is_undefined(value):
        return ''

    return '%s %s' % (arg_name, str(value))


def render(template_text, **kwargs):
    """Used to render a Jinja template."""

    loader = DictLoader({
        'template': template_text
    })

    env = Environment(loader=loader)
    env.filters['arg'] = arg_filter
    env.filters['yaml'] = yaml_filter
    template = env.get_template('template')

    return template.render(utils=sys.modules[__name__], **kwargs)


def wait_for(fn, *args, **kwargs):
    tries = 0
    while True:
        v = fn(*args, **kwargs)
        if v is None:
            if tries > 15:
                raise Exception('wait failed, tries exceeded')
            tries += 1

            log.info('waiting for %s...' % fn.__name__)
            time.sleep(10)


def retry(fn, *args, **kwargs):
    return retry2(fn, 5, *args, **kwargs)


def retry2(fn, max_attempts, *args, **kwargs):
    tries = 0
    while True:
        try:
            return fn(*args, **kwargs)
        except KeyboardInterrupt:
            raise
        except:
            if tries > max_attempts:
                raise
            tries += 1

            log.exception('failed to call %s, retrying in 10s...', fn.__name__)
            time.sleep(10)

def ssh(server, cmd, user=None, stdout=True, raise_error=True, sudo=False, exit_on_error=False, echo_command=True):
    cmd_array = ['ssh', '-T', '%s@%s' % (user, server),
                '-oPreferredAuthentications=publickey', '-oStrictHostKeyChecking=no']
    if stdout:
        p = subprocess.Popen(cmd_array, stdin=subprocess.PIPE)
    else:
        FNULL = open(os.devnull, 'w')
        p = subprocess.Popen(cmd_array, stdin=subprocess.PIPE, stdout=FNULL, stderr=FNULL)
    exit_cmd = ''
    echo_cmd = '\nset -x'
    if not echo_command:
        echo_cmd = ''
    if exit_on_error:
        exit_cmd = 'set -ae\n'
    if sudo:
        cmd = 'sudo bash <<-\'SUDO_EOF\'%s\n%s%s\nSUDO_EOF' % (echo_cmd, exit_cmd, cmd)
        p.communicate(cmd)
    else:
        p.communicate(exit_cmd + cmd)
    rc = p.returncode
    if raise_error and rc != 0:
        raise Exception('unable to run ssh command on %s [exitcode=%s]' % (server, rc))
    return rc


def extend(d, u):
    o = dict(d)
    for k, v in u.iteritems():
        if isinstance(v, collections.Mapping):
            r = extend(o.get(k, {}), v)
            o[k] = r
        elif isinstance(v, list):
            #o[k] = o.get(k, []) + v
            o[k] = v
        else:
            o[k] = u[k]
    return o


def cat_file(path, data):
    if isinstance(data, collections.Mapping):
        d = []
        for k in data:
            v = data[k]
            if isinstance(v, str):
                d.append('%s="%s"' % (k, v))
            else:
                d.append('%s=%s' % (k, v))
        content = '\n'.join(d)
    else:
        content = data

    return """
cat <<-'EOF' > {path}
{content}
EOF
""".format(content=content, path=path)
