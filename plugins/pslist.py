# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from typing import Callable, Iterable, List, Any
import logging

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility


vollog = logging.getLogger(__name__)


class PsList(interfaces.plugins.PluginInterface):
    """Lists the processes present in a particular linux memory image."""

    _required_framework_version = (2, 0, 0)

    _version = (2, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Linux kernel',
                                           architectures = ["Intel32", "Intel64"]),
            requirements.ListRequirement(name = 'pid',
                                         description = 'Filter on specific process IDs',
                                         element_type = int,
                                         optional = True),
            requirements.BooleanRequirement(name='nsinfo',
                                            description='Display namespace information',
                                            optional=True,
                                            default=False)
        ]

    @classmethod
    def create_pid_filter(cls, pid_list: List[int] = None) -> Callable[[Any], bool]:
        """Constructs a filter function for process IDs.

        Args:
            pid_list: List of process IDs that are acceptable (or None if all are acceptable)

        Returns:
            Function which, when provided a process object, returns True if the process is to be filtered out of the list
        """
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:

            def filter_func(x):
                return x.pid not in filter_list

            return filter_func
        else:
            return lambda _: False

    def _generator(self):
        for task in self.list_tasks(self.context,
                                    self.config['kernel'],
                                    filter_func = self.create_pid_filter(self.config.get('pid', None))):
            pid = task.pid
            ppid = 0
            if task.parent:
                ppid = task.parent.pid
            name = utility.array_to_string(task.comm)

            # don't extract namespace info
            if not self.config.get('nsinfo', False):
                yield (0, (pid, ppid, name))
            
            else:
                # Get namespace IDs.
                # This is full of try and excepts because different kernel versions
                # have different available namespace types.
                # If a certain namespace type does not exist, -1 is returned for its value.
                if task.has_member('nsproxy'):
                    nsproxy = task.nsproxy.dereference()

                    # get uts namespace
                    try:
                        uts_ns = nsproxy.get_uts_ns().get_inum()
                    except AttributeError:
                        uts_ns = -1
                    
                    # get ipc namespace
                    try:
                        ipc_ns = nsproxy.get_ipc_ns().get_inum()
                    except AttributeError:
                        ipc_ns = -1

                    # get mount namespace
                    try:
                        mnt_ns = nsproxy.get_mnt_ns().get_inum()
                    except AttributeError:
                        mnt_ns = -1
                    
                    # get net namespace
                    try:
                        net_ns = nsproxy.get_net_ns().get_inum()
                    except AttributeError:
                        net_ns = -1
                    
                    # get pid namespace
                    try:
                        pid_ns = task.get_pid_ns().get_inum()
                    except AttributeError:
                        pid_ns = -1
                    
                    # get user namespace
                    try:
                        user_ns = nsproxy.get_user_ns().get_inum()
                    except AttributeError:
                        user_ns = -1
                    
                    # get pid from within the namespace
                    try:
                        namespace_pid = task.get_namespace_pid()
                    except AttributeError:
                        namespace_pid = -1
                    
                    yield (0, (pid, ppid, name, namespace_pid, uts_ns, ipc_ns, mnt_ns, net_ns, pid_ns, user_ns))
                
                # no task -> nsproxy
                else:
                    vollog.error('Unable to extract namespace information (no task -> nsproxy member)')
                    return

    @classmethod
    def list_tasks(
            cls,
            context: interfaces.context.ContextInterface,
            vmlinux_module_name: str,
            filter_func: Callable[[int], bool] = lambda _: False) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Yields:
            Process objects
        """
        vmlinux = context.modules[vmlinux_module_name]

        init_task = vmlinux.object_from_symbol(symbol_name = "init_task")

        # Note that the init_task itself is not yielded, since "ps" also never shows it.
        for task in init_task.tasks:
            if not filter_func(task):
                yield task

    def run(self):
        columns = [('PID', int), ('PPID', int), ('COMM', str)]
        if self.config.get('nsinfo', False):
            columns.extend([('PID in NS', int), ('UTS NS', int), ('IPC NS', int), ('MNT NS', int), ('NET NS', int), ('PID NS', int), ('USER NS', int)])
        return renderers.TreeGrid(columns, self._generator())
