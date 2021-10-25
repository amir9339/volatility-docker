from typing import List
import logging
from datetime import datetime

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework import exceptions
from volatility3.framework.objects import utility

from volatility3.plugins.linux import pslist, mount, ifconfig

vollog = logging.getLogger(__name__)

DOCKER_MAC_VENDOR_STARTER       = "02:42"
DOCKER_INTERFACE_STARTER        = "docker"
VETH_NAME_STARTER               = "eth"
DOCKER_MOUNT_PATH               = "/var/lib/docker/"
CONTAINERD_SHIM_PROC_STARTER    = "containerd-shim"
OVERLAY                         = "overlay"
CONTAINERD_PROCESS_COMMAND      = "containerd-shim"
DOCKER_OVERLAY_DIR_PATH         = "/var/lib/docker/overlay"
MERGED_DIR                      = "merged"
MERGED_DIR_PATH_LEN             = 7
PRIV_CONTAINER_EFF_CAPS         = 274877906943 # 0x3fffffffff

MOUNTS_WHITELIST = (
    "-",
    "/var/lib/docker/overlay",
    "/sys/fs/cgroup",
)

CAPABILITIES = [
    # Defined at: https://elixir.bootlin.com/linux/v5.15-rc6/source/include/uapi/linux/capability.h
    "CAP_CHOWN", 
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP__SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE"
]

class Detector():
    """ This class has set of functions for docker detection on system """

    def __init__(self, context, vmlinux, tasks_list) -> None:
        self.context = context # Volatility req
        self.vmlinux = vmlinux # Volatility req
        self.tasks_list = tasks_list # Tasks objects list
        self.mounts = mount.Mount.get_all_mounts(self.context, self.vmlinux.name) # Get mounts from plugin
        self.net_devices = ifconfig.Ifconfig.get_devices_namespaces(self.context, self.vmlinux.name)

    def _detect_docker_network_interface(self, name, mac_addr) -> bool:
        """ 
        This function search for an docker standard interface. 
        Looking for an interface whose name starts with 'docker' and its MAC vendor starts with '02:42' (the last 4 bytes are calculated on the fly)
        """

        return name.startswith(DOCKER_INTERFACE_STARTER) and mac_addr.startswith(DOCKER_MAC_VENDOR_STARTER)

    def _detect_docker_veths(self, name, mac_addr) -> bool:
        """ 
        This function is looking for virtual interface that are used inside containers.
        Almost the same way as in _detect_docker_network_interface function.
        It looking for interfaces starting with the name 'eth' and the MAC address '02:42'
        """

        return name.startswith(VETH_NAME_STARTER) and mac_addr.startswith(DOCKER_MAC_VENDOR_STARTER)

    def _detect_overlay_fs(self, fstype, path) -> bool:
        """
        This function is looking for 'overlay' FS mounted inside docker standard path:
            /var/lib/docker/
        These FS are used as container's FS
        """

        return OVERLAY in fstype and path.startswith(DOCKER_MOUNT_PATH)
    
    def _detect_containerd_shim(self, proc_name) -> bool:
        """
        Containerd-shim is the parent process of all docker containers. Example can be seen in this output of `ps auxf` command:
            root        6398 713104  3120 16:00 /usr/bin/containerd-shim-runc-v2 -namespace moby -id
            root        6417   2508    68 16:00  \_ sleep 3000
        This function is looking for a process of containerd-shim in processes list
        """

        return CONTAINERD_SHIM_PROC_STARTER in proc_name

    def generate_detection_list(self):
        """ 
        This function generates a list of values that indicates a presence of containers / docker daemon on machine 
        """

        # Set default values
        docker_eth_exists, docker_veth_exists, overlay_fs_exists, container_shim_running = False, False, False, False

        # Get processes list from memory using pslist plugin
        for task in self.tasks_list:
            proc_name = utility.array_to_string(task.comm)
            
            if self._detect_containerd_shim(proc_name):
                container_shim_running = True
                break
        
        # Get mounts list from mem using mount plugin and look for overlay FS mounts inside docker's dir
        for mnt in self.mounts:

            id, pid, devname, path, abs_type, fstype, access, flags = mount.Mount.get_mount_info(mnt)

            if self._detect_overlay_fs(fstype, path):
                overlay_fs_exists = True
                break
    
        # Look for docker related interfaces
        for net_dev in self.net_devices:
            name, ip_addr, mac_addr, promisc = ifconfig.Ifconfig._gather_net_dev_info(self.context, self.vmlinux.name, net_dev)

            if self._detect_docker_network_interface(name, mac_addr):
                docker_eth_exists = True
            
            if self._detect_docker_veths(name, mac_addr):
                docker_veth_exists = True

        yield docker_eth_exists, docker_veth_exists, overlay_fs_exists, container_shim_running

class Ps():
    def __init__(self, context, vmlinux, tasks_list) -> None:
        self.context = context # Volatility req
        self.vmlinux = vmlinux # Volatility req
        self.tasks_list = tasks_list # Tasks objects list

    def get_containers_pids(self):
        """ 
        This function iterates each task in tasks list 
            and search for containerd-shim process. 
        After it found those processes it searches for
            processes that are bound to those shim processes 
            and returns their PIDs
        """

        containerd_shim_processes_pids = []
        containers_pids = []
        
        # Iterate processes list and search for "containerd-shim" processes which are bound to containers
        for task in self.tasks_list:
            comm = utility.array_to_string(task.comm)

            # If the process is an instance of containerd-shim, append it's process id to list
            if comm == CONTAINERD_PROCESS_COMMAND:
                containerd_shim_processes_pids.append(task.pid)

        # Search for containers that are bound to shim list
        for task in self.tasks_list:
            if task.parent.pid in containerd_shim_processes_pids:
                containers_pids.append(task.pid)
        return containers_pids
    
    def get_container_id(self, container_pid):
        """ 
        This function gets a PID of a container
        It enumerates process's mount points using linux.mount
        Then, it iterates container's process mounts and search for 
            container_id which is the name of container's dir
        """

        pid_filter = pslist.PsList.create_pid_filter([container_pid]) 
        process_mounts = mount.Mount.get_mounts(self.context, self.vmlinux.name, pid_filter) # Extract mounts for this process
        process_mounts = [mount.Mount.get_mount_info(mnt) for mnt in process_mounts] # Extract mount info for each mount point

        # Iterate each mount in mounts list
        for mnt_id, parent_id, devname, path, absolute_path, fs_type, access, flags in process_mounts:
            
            splitted_path = absolute_path.split("/")

            # Search for container's merged dir (container's FS) under overlay or overlay2 dir
            if absolute_path.startswith(DOCKER_OVERLAY_DIR_PATH) and absolute_path.endswith(MERGED_DIR) and len(splitted_path) == MERGED_DIR_PATH_LEN:
                container_id = splitted_path[-2] # Extract container_id from path
                return container_id
    
    def generate_list(self):
        """ 
        This function generates a list of running containers in this format:
        creation_time, command, container_id, is_priv, pid
        """

        containers_pids = self.get_containers_pids()
        
        # Search for container's tasks
        for task in self.tasks_list:
            for pid in containers_pids:
                if task.pid == pid:
                    command = utility.array_to_string(task.comm)
                    container_id = self.get_container_id(task.pid)

                    # Extract creds from task and check if container runs as priv. Note that there is a class that checks the exact container's creds
                    task_info = pslist.PsList.get_task_info(self.context, self.vmlinux.name, task, credinfo=True)
                    creation_time = task_info.start_time
                    creation_time = datetime.utcfromtimestamp(creation_time).isoformat(sep=' ', timespec='milliseconds')
                    effective_uid = task_info.eff_uid
                    is_priv = task_info.cap_eff == PRIV_CONTAINER_EFF_CAPS

                    yield creation_time, command, container_id, is_priv, pid, effective_uid
    
class InspectCaps():
    """ This class has methods for capabilites extraction and convertion """

    def __init__(self, context, vmlinux, tasks_list, containers_pids) -> None:
        """
        tasks_list - A list of tasks, extracted from memory using Pslist plugin
        containers_pids - A list of containers pids to inspect 
        """

        self.context = context # Volatility req
        self.vmlinux = vmlinux # Volatility req
        self.tasks_list = tasks_list
        self.containers_pids = containers_pids

    def _caps_hex_to_string(self, caps) -> list:
        """ 
        Linux active capabilities are saved as a bits sequense where each bit is a flag for each capability.
        This function iterate each flag in seq and if it's active it adds the specific capability to the list as a string represents it's name.
        """
        
        active_caps = []
        caps = abs(caps) # The method below doesn't work for negative numbers
        
        bits_seq = bin(caps)[2:]
        bits_seq = bits_seq[::-1] # Reverse flags seq

        # For each flag in caps sequense, if cap is active, append to list
        for i, digit in enumerate(bits_seq):
            
            # If flag is active, append the right cap to the list
            if digit == "1":
                active_caps.append(CAPABILITIES[i])
        return active_caps
    
    def generate_containers_caps_list(self):
        """ This function iterate each container pid and convert its effective capabilities to list of caps """

        # Iterate each pid in containers list and search for it's task
        for pid in self.containers_pids:
            for task in self.tasks_list:
                if task.pid == pid:

                    # Get container-id from Ps class
                    container_id = Ps(self.context, self.vmlinux, self.tasks_list).get_container_id(pid)
                    
                    # Get task's creds
                    task_info = pslist.PsList.get_task_info(self.context, self.vmlinux.name, task, credinfo=True)
                    effective_caps = task_info.cap_eff
                    effective_caps_list = self._caps_hex_to_string(effective_caps)
                    yield pid, container_id, hex(effective_caps), ','.join(effective_caps_list)

class InspectMounts():
    """ This class has methods for interesting mounts extraction """

    def __init__(self, context, vmlinux, tasks_list, containers_pids) -> None:
        """
        tasks_list - A list of tasks, extracted from memory using Pslist plugin
        containers_pids - A list of containers pids to inspect 
        """

        self.context = context # Volatility req
        self.vmlinux = vmlinux # Volatility req
        self.tasks_list = tasks_list
        self.containers_pids = containers_pids

    def generate_mounts_list(self):
        """
        This function generates a list of containers unusual mount points.
        For each container that Ps class found it checks for mounts in it mount namespace 
            and compare it with it a whitelist that contains normal mounts paths.
        It returns: container pid, container_id and details about the mount taken from linux.mount.
        """

        # For each container, check for unusual mounts        
        for pid in self.containers_pids:
            pid_filter = pslist.PsList.create_pid_filter([pid]) 
            process_mounts = mount.Mount.get_mounts(self.context, self.vmlinux.name, pid_filter) # Extract mounts for this process
            process_mounts = [mount.Mount.get_mount_info(mnt) for mnt in process_mounts] # Extract mount info for each mount point

            # Iterate each mount in mounts list
            for mnt_id, parent_id, devname, path, absolute_path, fs_type, access, flags in process_mounts:
                if not absolute_path.startswith(MOUNTS_WHITELIST):
                    
                    # Get container-id from Ps class
                    container_id = Ps(self.context, self.vmlinux, self.tasks_list).get_container_id(pid)
                    yield pid, container_id, mnt_id, parent_id, devname, path, absolute_path, fs_type, access, flags

class NetworkLs():
    def __init__(self, context, vmlinux) -> None:
        self.context = context # Volatility req
        self.vmlinux = vmlinux # Volatility req
        self.net_devices = ifconfig.Ifconfig.get_devices_namespaces(self.context, self.vmlinux.name)

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
                                                version = (1, 0, 0)),
                
                # Plugin options
                requirements.BooleanRequirement(name='detector',
                                            description='Detect Docker daemon / containers in memory',
                                            optional=True,
                                            default=False),
                requirements.BooleanRequirement(name='ps',
                                            description='List containers',
                                            optional=True,
                                            default=False),
                requirements.BooleanRequirement(name='inspect-caps',
                                            description='Inspect container\'s capabilities ',
                                            optional=True,
                                            default=False),
                requirements.BooleanRequirement(name='inspect-mounts',
                                            description='Inspect container\'s mounts',
                                            optional=True,
                                            default=False),
                ]

    def _generator(self):

        vmlinux = self.context.modules[self.config['kernel']]

        tasks_list = list(pslist.PsList.list_tasks(self.context, vmlinux.name)) # Generate tasks list from memory using linux.pslist

        # If user chose detector, generate detection table
        if self.config.get("detector"):
            detection_values = Detector(self.context, vmlinux ,tasks_list).generate_detection_list()
            
            # Actually there is only one row...
            for row in detection_values:
                yield (0, row)

        # If user chose ps, generate containers list
        if self.config.get("ps"):
            for container_row in Ps(self.context, vmlinux ,tasks_list).generate_list():
                yield (0, container_row)

        # If user chose inspect-caps, generate containers list and check their capabilities
        if self.config.get("inspect-caps"):
            containers_pids = Ps(self.context, vmlinux ,tasks_list).get_containers_pids()
            for container_row in InspectCaps(self.context, vmlinux, tasks_list, containers_pids).generate_containers_caps_list():
                yield (0, container_row)
        
        # If user chose inspect-mounts, generate containers list and check their mounts
        if self.config.get("inspect-mounts"):
            containers_pids = Ps(self.context, vmlinux ,tasks_list).get_containers_pids()
            for container_row in InspectMounts(self.context, vmlinux, tasks_list, containers_pids).generate_mounts_list():
                yield (0, container_row)

    def run(self):

        columns = []

        if not self.config.get("detector") and not self.config.get("ps") \
            and not self.config.get("inspect-caps") and not self.config.get("inspect-mounts"):
            vollog.error(f'No option selected')
            raise exceptions.PluginRequirementException('No option selected')

        if self.config.get("detector"):
            columns.extend([('Docker inetrface', bool), ('Docker veth', bool), 
                            ('Mounted overlay FS', bool), ('Containerd-shim is running', bool)])

        if self.config.get("ps"):
            columns.extend([('Creation time (UTC)', str), ('Command', str), ('Container ID', str),
                            ('Is privileged', bool), ('PID', int), ('Effective UID', int)])
        
        if self.config.get("inspect-caps"):
            columns.extend([('PID', int), ('Container ID', str), ('Effective capabilities value', str), ('Effective capabilities names', str)])
        
        if self.config.get("inspect-mounts"):
            columns.extend([('PID', int), ('Container ID', str), ('Mount ID', int), 
                            ('Parent ID', int) ,('Device name', str), ('Path', str), 
                            ('Absolute Path', str), ('FS type', str), ('Access', str),
                            ('Flags', str)])

        return renderers.TreeGrid(columns, self._generator())