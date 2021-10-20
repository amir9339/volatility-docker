from typing import List
import logging

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility

from volatility3.plugins.linux import pslist, mount, ifconfig, docker_config

vollog = logging.getLogger(__name__)

DOCKER_MAC_VENDOR_STARTER       = docker_config.DOCKER_MAC_VENDOR_STARTER
DOCKER_INTERFACE_STARTER        = docker_config.DOCKER_INTERFACE_STARTER
VETH_NAME_STARTER               = docker_config.VETH_NAME_STARTER
DOCKER_MOUNT_PATH               = docker_config.DOCKER_MOUNT_PATH
CONTAINERD_SHIM_PROC_STARTER    = docker_config.CONTAINERD_SHIM_PROC_STARTER
OVERLAY                         = docker_config.OVERLAY

class DockerDetector():
    """ This class has set of functions for docker detection on system """

    def detect_docker_network_interface(self, name, mac_addr) -> bool:
        """ 
        This function search for an docker standard interface. 
        Looking for an interface whose name starts with 'docker' and its MAC vendor starts with '02:42' (the last 4 bytes are calculated on the fly)
        """

        return name.startswith(DOCKER_INTERFACE_STARTER) and mac_addr.startswith(DOCKER_MAC_VENDOR_STARTER)

    def detect_docker_veths(self, name, mac_addr) -> bool:
        """ 
        This function is looking for virtual interface that are used inside containers.
        Almost the same way as in detect_docker_network_interface function.
        It looking for interfaces starting with the name 'eth' and the MAC address '02:42'
        """

        return name.startswith(VETH_NAME_STARTER) and mac_addr.startswith(DOCKER_MAC_VENDOR_STARTER)

    def detect_overlay_fs(self, fstype, path) -> bool:
        """
        This function is looking for 'overlay' FS mounted inside docker standard path:
            /var/lib/docker/
        These FS are used as container's FS
        """

        return OVERLAY in fstype and path.startswith(DOCKER_MOUNT_PATH)
    
    def detect_containerd_shim(self, proc_name) -> bool:
        """
        Containerd-shim is the parent process of all docker containers. Example can be seen in this output of `ps auxf` command:
            root        6398 713104  3120 16:00 /usr/bin/containerd-shim-runc-v2 -namespace moby -id
            root        6417   2508    68 16:00  \_ sleep 3000
        This function is looking for a process of containerd-shim in processes list
        """

        return CONTAINERD_SHIM_PROC_STARTER in proc_name

class Docker(interfaces.plugins.PluginInterface) :
    """ Main class for docker plugin """

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.ModuleRequirement(name='kernel',
                                            description='Linux kernel',
                                            architectures=['Intel32', 'Intel64']),
                requirements.PluginRequirement(name = 'pslist',
                                                plugin = pslist.PsList, 
                                                version = (2, 0, 0)),
                requirements.PluginRequirement(name = 'mount', 
                                                plugin = mount.Mount, 
                                                version = (1, 0, 0)),
                requirements.PluginRequirement(name = 'ifconfig', 
                                                plugin = ifconfig.Ifconfig, 
                                                version = (1, 0, 0))]

    def _generator(self):

        vmlinux = self.context.modules[self.config['kernel']]

        docker_eth_exists, docker_veth_exists, overlay_fs_exists, container_shim_running = False, False, False, False

        # Get processes list from memory using pslist plugin
        for task in pslist.PsList.list_tasks(self.context, vmlinux.name):
            proc_name = utility.array_to_string(task.comm)
            
            if DockerDetector().detect_containerd_shim(proc_name):
                container_shim_running = True
                break
        
        # Get mounts list from mem using mount plugin and look for overlay FS mounts inside docker's dir
        for mnt in mount.Mount.get_all_mounts(self.context, vmlinux.name):

            id, pid, devname, path, abs_type, fstype, access, flags = mount.Mount.get_mount_info(mnt)

            if DockerDetector().detect_overlay_fs(fstype, path):
                overlay_fs_exists = True
                break
    
        
        # Look for docker related interfaces
        for net_dev in ifconfig.Ifconfig.get_devices_namespaces(self.context, vmlinux.name):
            name, ip_addr, mac_addr, promisc = ifconfig.Ifconfig._gather_net_dev_info(net_dev)

            if DockerDetector().detect_docker_network_interface(name, mac_addr):
                docker_eth_exists = True
            
            if DockerDetector().detect_docker_network_interface(name, mac_addr):
                container_shim_running = True

        yield (0, [docker_eth_exists, docker_veth_exists, overlay_fs_exists, container_shim_running])
    
    def run(self):
        return renderers.TreeGrid([('Docker inetrface', bool), ('Docker veth', bool), ('Mounted overlay FS', bool), ('Containerd-shim is running', bool)], self._generator())
