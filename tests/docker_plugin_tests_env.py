import json
from datetime import datetime

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


with open("tests/output_from_vol/pslist_cred.json") as f:
    f = f.read()
    pslist = json.loads(f)

with open("tests/output_from_vol/mount_pid_6343.json") as f:
    f = f.read()
    container_mounts = json.loads(f)

############################################################

CONTAINERD_PROCESS_COMMAND = "containerd-shim"
DOCKER_OVERLAY_DIR_PATH = "/var/lib/docker/overlay"
MERGED_DIR = "merged"
MERGED_DIR_PATH_LEN = 7
PRIV_CONTAINER_EFF_CAPS = 274877906943


class Ps():
    def __init__(self, tasks_list) -> None:
        self.tasks_list = tasks_list

    def get_containers_pids(self):
        """ 
        This function iterates each task in tasks list 
            and search for containerd-shim process. 
        After it found those processes it searches for
            processes that are bound to those shim processes 
            and returns their PIDs
        """
        containerd_processes_pids = list()
        containers_pids = list()

        # Iterate processes list and search for "containerd-shim" processes which are bound to containers
        for ps in self.tasks_list:

            # If the process is an instance of containerd-shim, append it's process id to list
            if ps["COMM"] == CONTAINERD_PROCESS_COMMAND:
                containerd_processes_pids.append(ps["PID"])

        # Search for containers that are bound to shim list
        for ps in self.tasks_list:
            if ps["PPID"] in containerd_processes_pids:
                containers_pids.append(ps["PID"])

        return containers_pids

    def get_container_id(self, process_mounts):
        """ 
        This function gets a PID of a container 
            and it iterates container's process mounts and search for 
            container_id which is the name of container's dir
        """
        # Iterate each mount in mounts list
        for mount in process_mounts:
            path = mount["Absolute Path"]
            splitted_path = path.split("/")

            # Search for container's merged dir (container's FS) under overlay or overlay2 dir
            if path.startswith(DOCKER_OVERLAY_DIR_PATH) and path.endswith(MERGED_DIR) and len(splitted_path) == MERGED_DIR_PATH_LEN:
                # Extract container_id from path
                container_id = splitted_path[-2]
                return container_id

    def generate_list(self):
        """ 
        This function generates a list of running containers in this format:
        container_id, command, created, is_privileged, pid
        """
        containers_pids = self.get_containers_pids()

        # Search for container's tasks
        for task in self.tasks_list:
            for pid in containers_pids:
                if task["PID"] == pid:
                    creation_time = ""
                    command = task["COMM"]
                    container_id = self.get_container_id(container_mounts)
                    is_priv = task["CapEff"] == PRIV_CONTAINER_EFF_CAPS
                    yield creation_time, command, container_id, is_priv, pid


class InspectCaps():
    """ This class has methods for capabilites extraction and convertion """

    def __init__(self, tasks_list, containers_pids) -> None:
        """
        tasks_list - A list of tasks, extracted from memory using Pslist plugin
        containers_pids - A list of containers pids to inspect 
        """
        self.tasks_list = tasks_list
        self.containers_pids = containers_pids

    def _caps_hex_to_string(self, caps) -> list:
        """ 
        Linux active capabilities are saved as a bits sequense where each bit is a flag for each capability.
        This function iterate each flag in seq and if it's active it adds the specific capability to the list as a string represents it's name.
        """
        active_caps = list()
        caps = abs(caps)  # The method below doesn't work for negative numbers

        bits_seq = bin(caps)[2:]
        bits_seq = bits_seq[::-1]  # Reverse flags seq

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
                if task["PID"] == pid:
                    effective_caps = task["CapEff"]
                    effective_caps_list = self._caps_hex_to_string(
                        effective_caps)
                    yield pid, effective_caps, effective_caps_list


docker_ps = Ps(pslist)
containers_pids = docker_ps.get_containers_pids()

print(docker_ps.get_container_id(container_mounts))
docker_ps.generate_list()

InspectCaps(pslist, containers_pids).generate_containers_caps_list()
