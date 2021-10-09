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
        net_namespace_list = net_namespace_list.cast("net") # Convert list to a net objects list

        # Walk each network namespace
        for ns in net_namespace_list.list:
            
            # Walk network devices list inside each namespace
            first = ns.dev_base_head.next.dereference().cast('net_device')
            for net_dev in first.dev_list:
                yield net_dev

    def _parse_mac_addr_from_net_dev(self, net_dev):
        """ 
        This func gets a net_dev object and returns an MAC asdress in a standard format.
        It only parses perm_addr array from net_device struct 
        """

        # If net_dev symbol has perm_addr member (An array which represents MAC addr) get it.
        if net_dev.has_member("perm_addr"):
            hwaddr = net_dev.perm_addr
            return ":".join(["{0:02x}".format(x) for x in hwaddr][:6]) # Join address in the standard format    
    
    def _parse_promisc_mode_from_net_dev(self, net_dev):
        """ 
        This function returns True if the device is in promiscous mode and False if its not
        The function checks the flags that are an int property of net_device struct
        """
        return net_dev.flags & 0x100 == 0x100
    
    def _parse_ifa_value(self, net_dev):
        """ 
        This function handles ifa_list - (Interfaces list) of a net_device object
        It walk on each member in the list and returns it's IP address and it's name (label) 
        This answer describes the full chain from net_device to IP address: 
            https://stackoverflow.com/questions/59382141/obtain-interface-netmask-in-linux-kernel-module
        """

        in_device = net_dev.ip_ptr.cast('in_device')
        ifa_list = in_device.ifa_list

        # TODO: FIX
        # Walk each interface in this list
        while ifa_list:
            ip_addr = ifa_list.ifa_address
            name = ifa_list.ifa_label
            name = utility.array_to_string(name)
            print(ip_addr, name)

            ifa_list = ifa_list.ifa_next

    def _gather_net_dev_info(self, net_dev):
        mac_addr, promisc = None, None

        try:
            mac_addr = self._parse_mac_addr_from_net_dev(net_dev)
            promisc = str(self._parse_promisc_mode_from_net_dev(net_dev))            
            #name, ip_addr = self._parse_ifa_value(net_dev)
        except exceptions.PagedInvalidAddressException:
            pass
        
        try:
            in_dev = net_dev.ip_ptr.cast('in_device') # Get inet (internet) device struct

            ifa_list = in_dev.ifa_list
            while ifa_list != None:
                ifa_address = ifa_list.ifa_address
                print(utility.array_to_string(ifa_address, 100))

                ifa_list = ifa_list.ifa_next

        except exceptions.PagedInvalidAddressException:
                pass
        
        if mac_addr:
            return "name", "ip_addr", mac_addr, promisc
        return "0", "0", "0", "0"
                               
            

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Linux kernel',
                                           architectures = ["Intel32", "Intel64"]),
        ]

    def _generator(self):
        
        # Gather all devices
        for net_dev in self._get_devices_namespaces(self.context, self.config['kernel']):
            name, ip_addr, mac_addr, promisc = self._gather_net_dev_info(net_dev)

            if name != "0":
                yield (0, (name, ip_addr, mac_addr, promisc))

    def run(self):
        return renderers.TreeGrid([("Interface", str), ("IP Address", str), ("MAC Adress", str), ("Promiscous Mode", str)], self._generator())
