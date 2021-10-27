from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import context
from volatility3.framework.objects import utility, Array


class Mount(interfaces.plugins.PluginInterface):
    """Lists all mounted filesystems."""

    _required_framework_version = (1, 2, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.ModuleRequirement(name='kernel', description='Linux kernel', architectures=['Intel32', 'Intel64'])]

    @classmethod
    def get_filesystem_types(cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str) -> dict:
        vmlinux = context.modules[vmlinux_module_name]
        fs_types = dict()

        fs_ptr = vmlinux.object_from_symbol(symbol_name='file_systems')

        while fs_ptr:
            fs = fs_ptr.dereference()
            fs_name = utility.pointer_to_string(fs.name, 256)
            print(fs_name)
            fs_types[fs_name] = fs
            fs_ptr = fs.next

        return fs_types

    @classmethod
    def list_mounts(cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str):
        vmlinux = context.modules[vmlinux_module_name]
        fs_types = cls.get_filesystem_types(context, vmlinux_module_name)

        if vmlinux.has_type('mount'):
            mnt_type = 'mount'
        else:
            mnt_type = 'vfsmount'

        mount_hashtable_ptr = vmlinux.object_from_symbol(
            symbol_name='mount_hashtable')
        mount_list_ptrs = vmlinux.object(object_type='array',
                                         offset=mount_hashtable_ptr,
                                         subtype=vmlinux.get_type(
                                             'hlist_head'),
                                         count=8200,
                                         absolute=True)

        non_empty = list()
        for mount_list_ptr in mount_list_ptrs:
            if mount_list_ptr.first != 0:
                non_empty.append(mount_list_ptr)

        mount_list_ptrs = set(non_empty)

    def _generator(self):
        self.list_mounts(self.context, self.config['kernel'])
        # for mount in self.list_mounts(self.context, self.config['kernel']):
        #    pass

        yield (0, (0, 0, 0))

    def run(self):
        return renderers.TreeGrid([("PLACEHOLDER", int), ("PLACEHOLDER2", int), ("PLACEHOLDER3", int)], self._generator())
