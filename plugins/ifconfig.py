from typing import List
import logging

from volatility3.framework import exceptions, renderers, constants, interfaces 
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import conversion
from volatility3.framework.objects import utility

MAX_STRING  = 256
IFNAMSIZ    = 16 # This is a constant for if (interface) name size (a property of net_device struct)
                 #  https://elixir.bootlin.com/linux/latest/source/include/linux/netdevice.h#L1932

vollog = logging.getLogger(__name__)

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
        This function searches for net neamespaces lists and extract all net devices from them
        
        e.g, ns = Namespace
        """

        vmlinux = context.modules[vmlinux_module_name]
        net_namespace_list = vmlinux.object_from_symbol(symbol_name = "net_namespace_list") # Get net_namespace_list object which is a list_head object
        
        # Enumerate each network namespace (struct net) in memory and pass the first one 
        for i, net_ns in enumerate(net_namespace_list.to_list('symbol_table_name1!net', 'list', sentinel=False)):
            if i == 0:
                continue

            # Each network ns holds interfaces list. Walk each interface 
            for interface in net_ns.dev_base_head.to_list('symbol_table_name1' + constants.BANG + 'net_device', 'dev_list', sentinel=True):
                
                # If appears
                if interface.name:
                    yield interface
    
    @classmethod
    def _get_devs_base(self,         
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str):
        """
        ! This function has not been properly tested !
        The function searches for net_device object and walk it's internal list
        """

        vmlinux = context.modules[vmlinux_module_name]
        net_device_ptr = vmlinux.object_from_symbol(symbol_name = "dev_base")
        net_device = net_device_ptr.dereference()

        for net_dev in net_device.dev_list:
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

        in_device = net_dev.ip_ptr
        ifa_list = in_device.ifa_list

        # TODO: FIX
        # Walk each interface in this list
        while ifa_list:
            ip_addr = ifa_list.ifa_address
            ip_addr = conversion.convert_ipv4(ip_addr) # Convert IP address from intiger to a valid string
            
            name = ifa_list.ifa_label # Interface name from interface struct (struct in_ifaddr)
            name = utility.array_to_string(name)
            ifa_list = ifa_list.ifa_next
            return (name, ip_addr)
        return "", ""


    def _gather_net_dev_info(self, net_dev):
        """ 
        This function gets a net_dev object and tries to extract the data from it using other functions.
        If its get an "Invalid Page" exception it does nothing :()
        """

        try:
            mac_addr = self._parse_mac_addr_from_net_dev(net_dev)
            promisc = str(self._parse_promisc_mode_from_net_dev(net_dev))            
            name, ip_addr = self._parse_ifa_value(net_dev)
        except exceptions.PagedInvalidAddressException:
            pass
                
        if mac_addr:
            return name, ip_addr, mac_addr, promisc
        return "0", "0", "0", "0"
                               
            

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Linux kernel',
                                           architectures = ["Intel32", "Intel64"]),
        ]

    def _generator(self):

        vmlinux_module_name = self.config['kernel']
        vmlinux = self.context.modules[vmlinux_module_name]
        
        # Newer kernels
        if vmlinux.has_symbol("net_namespace_list"):
            func = self._get_devices_namespaces
        elif vmlinux.has_symbol("dev_base"):
            func = self._get_devs_base
        else:
            vollog.error("Unable to determine ifconfig information. Probably because it's an old kernel")
            return
        
        # Gather all devices
        for net_dev in func(self.context, self.config['kernel']):
            name, ip_addr, mac_addr, promisc = self._gather_net_dev_info(net_dev)

            yield (0, (name, ip_addr, mac_addr, promisc))

    def run(self):
        return renderers.TreeGrid([("Interface name", str), ("IP Address", str), ("MAC Adress", str), ("Promiscous Mode", str)], self._generator())
