"""
Manages the plugins.
"""

import importlib
import os
import fnmatch
import imp

class PluginManager(object):
    def __init__(self, options):
        self._plugin_dir = os.path.dirname(__file__)
        self._plugins = self.get_plugins(self._plugin_dir, options)

    def get_plugins(self, plugin_dir, options):
        plugins = []

        if os.path.exists(plugin_dir):
            files = os.listdir(plugin_dir)
            for f in files:
                if not fnmatch.fnmatch(f, '__init__.py') and fnmatch.fnmatch(f, '*.py'):
                     script_path = os.path.join(plugin_dir, f)
                     plugin_source = imp.load_source('%s' % os.path.splitext(f)[0], script_path)
                     plugins.append(plugin_source.Plugin(options))

        return plugins

    def on_event(self, event_name, *args):
        for plugin in self._plugins:
            if hasattr(plugin, event_name):
                fn = getattr(plugin, event_name)
                fn(*args)


    def load_plugin(self, name):
        mod = importlib.import_module(name)
        return mod

    def on_before_server_pulled(self, server):
        self.on_event('on_before_server_pulled', server)

    def on_server_deleted(self, server):
        self.on_event('on_server_deleted', server)

    def on_server_pushed(self, server):
        self.on_event('on_server_pushed', server)

    def on_describe(self, server, info):
        self.on_event('on_describe', server, info)
    
    def on_before_server_created(self, server, options):
        self.on_event('on_before_server_created', server, options)