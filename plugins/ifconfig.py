from typing import Iterable, List, Tuple
import logging

from volatility3.framework import exceptions, renderers, constants, interfaces, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import conversion
from volatility3.framework.objects import utility

MAX_STRING  = 256
IFNAMSIZ    = 16 # This is a constant for if (interface) name size (a property of net_device struct)
                 # https://elixir.bootlin.com/linux/latest/source/include/linux/netdevice.h#L1932

vollog = logging.getLogger(__name__)

class Ifconfig(interfaces.plugins.PluginInterface):
    """ Ifconfig emulation plugin """

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_devices_namespaces(cls,         
                               context: interfaces.context.ContextInterface,
                               vmlinux_module_name: str) -> Iterable[interfaces.objects.ObjectInterface]:
        """Walk the list of net namespaces and extract all net devices from them (kernel >= 2.6.24)."""
        vmlinux = context.modules[vmlinux_module_name]
        symbol_table = vmlinux.symbol_table_name

        net_namespace_list = vmlinux.object_from_symbol(symbol_name='net_namespace_list')
        
        # Enumerate each network namespace (struct net) in memory and pass the first one 
        for net_ns in net_namespace_list.to_list(symbol_table + constants.BANG + 'net', 'list', sentinel=True):
            # for each net namespace, walk the list of net devices
            for net_dev in net_ns.dev_base_head.to_list(symbol_table + constants.BANG + 'net_device', 'dev_list', sentinel=True):
                yield net_dev
    
    @classmethod
    def _get_devs_base(cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str) -> Iterable[interfaces.objects.ObjectInterface]:
        """Walk the list of net devices headed by dev_base (kernel < 2.6.22)."""
        vmlinux = context.modules[vmlinux_module_name]

        first_net_device = vmlinux.object_from_symbol(symbol_name='dev_base').dereference()

        for net_dev in symbols.linux.LinuxUtilities.walk_internal_list(vmlinux, 'net_device', 'next', first_net_device):
            yield net_dev

    @classmethod
    def _parse_mac_addr_from_net_dev(cls, context, vmlinux_module_name, net_dev):
        """ 
        This func gets a net_dev object and returns an MAC asdress in a standard format.
        It only parses perm_addr array from net_device struct 
        """
        vmlinux = context.modules[vmlinux_module_name]
        symbol_table = vmlinux.symbol_table_name

        hw_addr_list = net_dev.dev_addrs
        for netdev_hw_addr in hw_addr_list.list.to_list(symbol_table + constants.BANG + 'netdev_hw_addr', 'list', sentinel=True):
            hwaddr = netdev_hw_addr.addr
            return ":".join(["{0:02x}".format(x) for x in hwaddr][:6])

        # If net_dev symbol has perm_addr member (An array which represents MAC addr) get it.
        if net_dev.has_member("perm_addr"):
            hwaddr = net_dev.perm_addr
            return ":".join(["{0:02x}".format(x) for x in hwaddr][:6]) # Join address in the standard format
    
    @classmethod
    def _parse_promisc_mode_from_net_dev(cls, net_dev):
        """ 
        This function returns True if the device is in promiscous mode and False if its not
        The function checks the flags that are an int property of net_device struct
        """
        return net_dev.flags & 0x100 == 0x100
    
    @classmethod
    def _parse_ifa_value(cls, net_dev):
        """ 
        This function handles ifa_list - (Interfaces list) of a net_device object
        It walk on each member in the list and returns it's IP address and it's name (label) 
        This answer describes the full chain from net_device to IP address: 
            https://stackoverflow.com/questions/59382141/obtain-interface-netmask-in-linux-kernel-module
        """
        in_device = net_dev.ip_ptr
        ifa_list = in_device.ifa_list
        name = utility.array_to_string(net_dev.name)

        # TODO: FIX
        # Walk each interface in this list
        while ifa_list:
            ip_addr = ifa_list.ifa_address
            ip_addr = conversion.convert_ipv4(ip_addr) # Convert IP address from integer to a valid string
            
            name = ifa_list.ifa_label # Interface name from interface struct (struct in_ifaddr)
            name = utility.array_to_string(name)
            ifa_list = ifa_list.ifa_next
            return (name, ip_addr)
        return name, ""

    @classmethod
    def _gather_net_dev_info(cls, context, vmlinux_module_name, net_dev: interfaces.objects.ObjectInterface) -> Tuple[str, str, str, str]:
        """Extract various information from a net device.
        Return the following tuple: name, ip addr, mac addr, is promiscuous.
        """
        """FIX ATTEMPT FINDINGS:
        The net_device struct has a few pointers to protocol-sepcific structs.
        ip_ptr points to a struct containing IPv4 specific info, and contains a list of in_ifaddr structs that contain info on an IPv4 address.
        Another important pointer is ip6_ptr (IPv6 info).
        2 more potentially important pointers are ieee80211_ptr and ieee802154_ptr (wireless stuff).
        While IPv4 address is obviously extracted from ip_ptr, other addresses are contained in the other structs.

        The first bug which I managed to find a fix for is the empty name for some interfaces.
        It happened because the name was extracted from the first entry in the list of IPv4 addresses.
        For interfaces with no IPv4 address, this list is empty so no name was extracted.
        The fix is to extract the name from the net_device struct itself (using the name field).

        The second bug is the empty mac address.
        The perm_addr field of net_device was used to get the mac address, but sometimes this field is empty.
        The solution (which I don't know whether it is applicable for older kernels) is to use the dev_addrs field,
        which is a netdev_hw_addr_list struct that holds a list of netdev_hw_addr structs.
        Each netdev_hw_addr struct contains a mac address in the addr field.
        Alternatively, the dev_addr field may be used. Problem is, this field changes from being a 6-byte array to a char pointer
        in newer kernels, so this must be taken into account. Also, I'm not sure what is the difference between this and the dev_addrs list.

        TL;DR:
        Each net device can have multiple IPv4 addresses, and multiple other types of addresses like IPv6 and wireless stuff.
        Name should be extracted from the net_device struct and not from an IPv4 address struct.
        A net device can have multiple MAC addresses and using the perm_addr field is incorrect.
        ALL THIS INFO IS SPECIFIC TO NEW KERNELS AND MAY BE DIFFERENT ON OLDER KERNELS.
        """
        try:
            mac_addr = cls._parse_mac_addr_from_net_dev(context, vmlinux_module_name, net_dev)
            promisc = str(cls._parse_promisc_mode_from_net_dev(net_dev))            
            name, ip_addr = cls._parse_ifa_value(net_dev)
        except exceptions.PagedInvalidAddressException:
            pass
                
        if mac_addr:
            return name, ip_addr, mac_addr, promisc
        return "0", "0", "0", "0"
                               
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel',
                                           description='Linux kernel',
                                           architectures=['Intel32', 'Intel64']),
        ]

    def _generator(self):
        vmlinux_module_name = self.config['kernel']
        vmlinux = self.context.modules[vmlinux_module_name]
        
        # kernel >= 2.6.24
        if vmlinux.has_symbol('net_namespace_list'):
            func = self.get_devices_namespaces
        # kernel < 2.6.22
        elif vmlinux.has_symbol('dev_base'):
            func = self._get_devs_base
        # kernel 2.6.22 and 2.6.23
        elif vmlinux.has_symbol('dev_name_head'):
            vollog.error('Cannot extract net devices from kernel versions 2.6.22 - 2.6.23')
            return
        # other unsupported kernels
        else:
            vollog.error("Unable to determine ifconfig information. Probably because it's an old kernel")
            return
        
        # Gather all devices
        for net_dev in func(self.context, self.config['kernel']):
            name, ip_addr, mac_addr, promisc = self._gather_net_dev_info(self.context, self.config['kernel'], net_dev)

            yield (0, (name, ip_addr, mac_addr, promisc))

    def run(self):
        return renderers.TreeGrid([("Interface name", str), ("IP Address", str), ("MAC Adress", str), ("Promiscous Mode", str)], self._generator())
