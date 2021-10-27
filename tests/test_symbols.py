from logging import exception
from typing import List

from volatility3.framework import exceptions, renderers, constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist


class PluginTest(interfaces.plugins.PluginInterface):
    """ Test Class """

    _required_framework_version = (1, 2, 0)

    _version = (2, 0, 0)

    # TODO: Check da fck
    if True:
        mnttype = "mount"
    else:
        mnttype = "vfsmount"

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux kernel',
                                           architectures=["Intel32", "Intel64"]),
        ]

    @classmethod
    def test_test(
            cls,
            context: interfaces.context.ContextInterface,
            vmlinux_module_name: str):

        vmlinux = context.modules[vmlinux_module_name]
        mount_hashtable = vmlinux.object_from_symbol(
            symbol_name="mount_hashtable")
        mount_hashtables = utility.array_of_pointers(
            mount_hashtable.dereference(),
            count=8200,
            subtype=vmlinux.symbol_table_name + constants.BANG + "hlist_head",
            context=context
        )

        mounts_ptrs = []

        # We assume that each pointer is a pointer to a doubly linked list
        #   contains mounts structs
        for pointer in mount_hashtables:

            if pointer == 0:
                continue
            mounts_ptrs.append(pointer)
        mounts_ptrs = list(set(mounts_ptrs))

        mnts = []
        # Iterate each mount pointer and get mount struct from it
        for hlist_head_ptr in mounts_ptrs:
            hlist_head = hlist_head_ptr.dereference()
            list_head_ptr = hlist_head.first
            list_head = list_head_ptr.cast('list_head')
            mnt = list_head.cast('mount')
            # mnt = vmlinux.object(object_type = "mount", offset = list_head.address)

            try:
                devname = utility.array_to_string(mnt.mnt_devname)
                print(devname)
            except Exception:
                pass

    def _generator(self):

        # Call test func
        self.test_test(
            self.context,
            self.config['kernel'],
        )

        for i in range(1):
            yield 0, (i, 2, "A")

    def run(self):
        return renderers.TreeGrid([("PID", int), ("PPID", int), ("COMM", str)], self._generator())
