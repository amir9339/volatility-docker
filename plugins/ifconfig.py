from logging import exception
from typing import List

from volatility3.framework import exceptions, renderers, constants, interfaces 
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility

MAX_STRING = 256

class Ifconfig(interfaces.plugins.PluginInterface):
    """ Ifconfig emulation plugin """

    _required_framework_version = (2, 0, 0)

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
        net_namespace_list = vmlinux.object_from_symbol(symbol_name = "net_namespace_list") # Get net_namespace_list object which is a list_head object 
        net_namespace_list = net_namespace_list.cast("net")

        for ns in net_namespace_list.list:
            #print(ns.ifindex)
            #for net_dev in ns.dev_base_head.to_list("net_device", "dev_list"):
            print('next namespace')
            first = ns.dev_base_head.next.dereference().cast('net_device')
            for net_dev in first.dev_list:
                print(net_dev.mac_addr)


        table_name = net_namespace_list.vol.type_name.split(constants.BANG)[0]

        # Walk each network name space in namespaces list
        for net in net_namespace_list.to_list(table_name + constants.BANG + "net", "list"):

            net_devices_list = net.dev_base_head.to_list(table_name + constants.BANG + "net_device", "dev_list")

            for net_device in net_devices_list:
                #print(dir(net_device))
                print((net_device.ip_ptr))
                ip_addr = utility.pointer_to_string(net_device.ip_ptr, MAX_STRING)

                #print(vmlinux.layer_name)
                in_device = context.object(table_name + constants.BANG + "in_device",
                    layer_name = vmlinux.layer_name,
                    offset = net_device.ip_ptr)

                #print(dir(in_device))
                print("\n")                

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
