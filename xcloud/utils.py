import collections
import logging
import os
import re
import subprocess
import time
from datetime import timedelta

from jinja2 import DictLoader
from jinja2 import Environment

log = logging.getLogger(__name__)


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


def render(template_text, **kwargs):
    """Used to render a Jinja template."""

    loader = DictLoader({
        'template': template_text
    })

    env = Environment(loader=loader)
    template = env.get_template('template')

    return template.render(**kwargs)


def wait_for(fn, *args, **kwargs):
    tries = 0
    while True:
        v = fn(*args, **kwargs)
        if v is None:
            if tries > 15:
                raise
            tries += 1

            log.info('waiting for %s...' % fn.__name__)
            time.sleep(10)


def retry(fn, *args, **kwargs):
    tries = 0
    while True:
        try:
            return fn(*args, **kwargs)
        except KeyboardInterrupt:
            exit(1)
        except:
            if tries > 5:
                raise
            tries += 1

            log.exception('failed to call %s, retrying in 10s...', fn.__name__)
            time.sleep(10)


def ssh(server, cmd, user=None, stdout=True, raise_error=True, sudo=False, exit_on_error=False):
    cmd_array = ['ssh', '-T', '%s@%s' % (user, server),
                '-oPreferredAuthentications=publickey', '-oStrictHostKeyChecking=no']
    if stdout:
        p = subprocess.Popen(cmd_array, stdin=subprocess.PIPE)
    else:
        FNULL = open(os.devnull, 'w')
        p = subprocess.Popen(cmd_array, stdin=subprocess.PIPE, stdout=FNULL, stderr=FNULL)
    exit_cmd = ''
    if exit_on_error:
        exit_cmd = 'set -ae\n'
    if sudo:
        cmd = 'sudo bash <<-\'SUDO_EOF\'\n%s%s\nSUDO_EOF' % (exit_cmd, cmd)
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
        else:
            o[k] = u[k]
    return o