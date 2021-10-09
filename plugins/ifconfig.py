from logging import exception
from typing import List

from volatility3.framework import exceptions, renderers, constants, interfaces 
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility

MAX_STRING = 256

class Ifconfig(interfaces.plugins.PluginInterface):
    """ Ifconfig emulation plugin """

    _required_framework_version = (1, 2, 0)

    _version = (2, 0, 0)

    @classmethod
    def _get_devices_namespaces(
        self,         
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str):
        """ 
        This function searches for net neamespaces list and extract all net devices from it
        
        e.g, ns = Namespace
        """

        vmlinux = context.modules[vmlinux_module_name]

        # Get network namespace list and define list_head
        nslist_addr = vmlinux.object_from_symbol(symbol_name = 'net_namespace_list')
        print(dir(nslist_addr))
        nslist = nslist_addr.cast("list_head")


    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Linux kernel',
                                           architectures = ["Intel32", "Intel64"]),
        ]

    def _generator(self):

        # Call test func
        self._get_devices_namespaces(
            self.context,
            self.config['kernel'],
        )

        for i in range(1):
            yield 0, ("", "", "", "")

    def run(self):
        return renderers.TreeGrid([("Interface", str), ("IP Address", str), ("MAC Adress", str), ("Promiscous Mode", str)], self._generator())
