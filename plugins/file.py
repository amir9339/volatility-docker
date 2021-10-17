from typing import Callable, List, Tuple, Set, Any, Union
import logging

from volatility3.framework import renderers, interfaces, symbols, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import mount as mount_plugin
from volatility3.plugins.linux import pslist
from volatility3.framework import exceptions


"""
TODO:
    - extract file permissions (drwxrwxrwx)
    - extract file size
    - extract created/modified/access times
    - extract owner
    - filter by file owner
"""


# masks for determining if an inode is a directory
# see https://elixir.bootlin.com/linux/v5.15-rc5/source/include/uapi/linux/stat.h
S_IFMT  = 0xf000
S_IFDIR = 0x4000

vollog = logging.getLogger(__name__)


class ListFiles(interfaces.plugins.PluginInterface):
    """Lists all files recursively under a specified path and/or in a specified mounted filesystem."""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel',
                                           description='Linux kernel',
                                           architectures=['Intel32', 'Intel64']),
            requirements.PluginRequirement(name='pslist',
                                           plugin=pslist.PsList,
                                           version=(2, 0, 0)),
            requirements.PluginRequirement(name='mount',
                                           plugin=mount_plugin.Mount,
                                           version=(1, 0, 0)),
            requirements.ListRequirement(name='pid',
                                         description='Use mounts from the mount namespaces of the specified PIDs',
                                         element_type=int,
                                         optional=True),
            requirements.ListRequirement(name='mount',
                                         description='Filter on specific mounts by mount ID',
                                         element_type=int,
                                         optional=True),
            requirements.StringRequirement(name='path',
                                           description='List files under a specified path',
                                           optional=True),
            requirements.BooleanRequirement(name='sort',
                                            description='Sort files by path',
                                            optional=True,
                                            default=True)
        ]
    
    @classmethod
    def create_mount_filter(cls, mnt_list: List[int] = None) -> Callable[[Any], bool]:
        """Constructs a filter function for mount IDs.
        Args:
            mnt_list: List of mount IDs that are acceptable (or None if all are acceptable)
        Returns:
            Function which, when provided a mount object, returns True if the mount is to be filtered out
        """
        if mnt_list is None:
            mnt_list = []
        filter_list = [x for x in mnt_list if x is not None]

        if filter_list:

            def filter_func(mount):
                return mount.mnt_id not in filter_list

            return filter_func
        else:
            return lambda _: False
    
    @classmethod
    def create_path_filter(cls, path) -> Callable[[Any], bool]:
        """Constructs a filter function for file paths.
        Args:
            path: Path that must be contained in the files to be listed
        Returns:
            Function which, when provided a file path, returns True if the path is to be filtered out
        """
        if path is None:
            path = ''

        def filter_func(x):
            return not x.startswith(path)
        
        return filter_func

    @classmethod
    def get_file_info(cls,
                      mount: symbols.linux.extensions.mount,
                      dentry: symbols.linux.extensions.dentry) -> Union[None, Tuple[int, int, int, str]]:
        """
        Parse a mount and dentry pair and return the following tuple:
        mount_id, inode_id, inode_address, file_path
        """
        # get file path
        sb = mount.get_mnt_sb()
        s_root = sb.s_root.dereference()
        mnt_parent = mount.mnt_parent.dereference()
        try:
            path = symbols.linux.LinuxUtilities._do_get_path(s_root, mnt_parent, dentry, mount)
        # bad dentry
        except exceptions.PagedInvalidAddressException:
            return None

        # get mount id
        mnt_id = mount.mnt_id

        # get inode ID and address
        try:
            inode_id = dentry.d_inode.dereference().i_ino
            inode_addr = int(dentry.d_inode)
        # bad inode
        except exceptions.PagedInvalidAddressException:
            inode_id = -1
            inode_addr = 0

        return mnt_id, inode_id, inode_addr, path
    
    @classmethod
    def _walk_dentry(cls,
                     context: interfaces.context.ContextInterface,
                     vmlinux_module_name: str,
                     dentry_set: Set[symbols.linux.extensions.dentry],
                     dentry: symbols.linux.extensions.dentry):
        """Walks a dentry recursively, adding all child dentries to the given list."""
        vmlinux = context.modules[vmlinux_module_name]
        symbol_table = vmlinux.symbol_table_name

        # we've seen this dentry
        if dentry.vol.offset in dentry_set:
            return

        # add dentry to list
        dentry_set.add(dentry.vol.offset)

        # check if this is a directory
        try:
            is_dir = dentry.d_inode.dereference().i_mode & S_IFMT == S_IFDIR
        except exceptions.PagedInvalidAddressException:
            return
        if is_dir:
            # walk subdirs linked list
            for subdir_dentry in dentry.d_subdirs.to_list(symbol_table + constants.BANG + 'dentry', 'd_child'):
                # walk subdir dentry
                cls._walk_dentry(context, vmlinux_module_name, dentry_set, subdir_dentry)
    
    @classmethod
    def get_dentries(cls,
                     context: interfaces.context.ContextInterface,
                     vmlinux_module_name: str,
                     pid_filter: Callable[[Any], bool] = None,
                     mnt_filter: Callable[[Any], bool] = lambda _: False) -> Tuple[symbols.linux.extensions.mount, List[symbols.linux.extensions.dentry]]:
        """Get a list of all cached dentries in the filesystem that match the given filters."""
        vmlinux = context.modules[vmlinux_module_name]

        # list of dentries
        dentries = []

        # get a list of mounts to use
        if pid_filter is None:
            non_filtered_mounts = mount_plugin.Mount.get_all_mounts(context, vmlinux_module_name)
        else:
            non_filtered_mounts = mount_plugin.Mount.get_mounts(context, vmlinux_module_name, pid_filter)
        
        # filter out mounts
        mounts = [mount for mount in non_filtered_mounts if not mnt_filter(mount)]
        num_mounts = len(mounts)

        for i, mount in enumerate(mounts):
            vollog.info(f'[{i}/{num_mounts}]  listing files for mount ID {mount.mnt_id}')
            
            # set of dentry addresses for this mount
            mount_dentries = set()

            # get the root dentry of this mount
            root_dentry = mount.get_mnt_root().dereference()

            # walk root dentry and extract all dentries recursively
            cls._walk_dentry(context, vmlinux_module_name, mount_dentries, root_dentry)

            # add dentries for this mount to global list
            for dentry_ptr in mount_dentries:
                dentry = vmlinux.object(object_type='dentry', offset=dentry_ptr, absolute=True)
                dentries.append((mount, dentry))
        
        return dentries
    
    def _generator(self):
        path_filter = self.create_path_filter(self.config.get('path', None))
        pids = self.config.get('pid', None)
        if pids is not None:
            pid_filter = pslist.PsList.create_pid_filter(pids)
        else:
            pid_filter = None

        files = dict()
        dentries = self.get_dentries(context=self.context,
                                     vmlinux_module_name=self.config['kernel'],
                                     pid_filter=pid_filter,
                                     mnt_filter=self.create_mount_filter(self.config.get('mount', None)))
        num_dentries = len(dentries)
        for i, (mount, dentry) in enumerate(dentries):
            # print info message every 1000 files
            if i % 1000 == 0:
                vollog.info(f'[{i}/{num_dentries}]  extracting file info and filtering paths')

            info = self.get_file_info(mount, dentry)
            # info could not be extracted
            if info is None:
                continue
            mnt_id, inode_id, inode_addr, file_path = info

            # path is not filtered out
            if not path_filter(file_path):
                files[file_path] = mnt_id, inode_id, inode_addr, file_path
        
        paths = list(files.keys())
        if self.config.get('sort', None):
            vollog.info('sorting files')
            paths.sort()
            vollog.info('done sorting')
        for path in paths:
            mnt_id, inode_id, inode_addr, file_path = files[path]
            yield (0, (mnt_id, inode_id, format_hints.Hex(inode_addr), file_path))
    
    def run(self):
        return renderers.TreeGrid([("Mount ID", int), ("Inode ID", int), ("Inode Address", format_hints.Hex), ("File Path", str)], self._generator())
