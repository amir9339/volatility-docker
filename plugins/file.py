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
    - extract file size
    - extract created/modified/access times
"""


# inode types
# see https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/stat.h
S_IFMT   = 0o170000 # inode type mask
S_IFSOCK = 0o140000 # socket
S_IFLNK  = 0o120000 # symbolic link
S_IFREG  = 0o100000 # regular file
S_IFBLK  = 0o60000  # block device
S_IFDIR  = 0o40000  # directory
S_IFCHR  = 0o20000  # character device
S_IFIFO  = 0o10000  # fifo (pipe)
S_ISUID  = 0o4000
S_ISGID  = 0o2000
S_ISVTX  = 0o1000

# user permissions
S_IRWXU = 0o700 # user permissions mask
S_IRUSR = 0o400 # user read
S_IWUSR = 0o200 # user write
S_IXUSR = 0o100 # user execute

# group permissions
S_IRWXG = 0o070 # group permissions mask
S_IRGRP = 0o040 # group read
S_IWGRP = 0o020 # group write
S_IXGRP = 0o010 # group execute

# other permissions
S_IRWXO = 0o007 # other permissions mask
S_IROTH = 0o004 # other read
S_IWOTH = 0o002 # other write
S_IXOTH = 0o001 # other execute


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
                                         description='List files from the mount namespaces of the specified PIDs',
                                         element_type=int,
                                         optional=True),
            requirements.ListRequirement(name='mount',
                                         description='Filter on specific mounts by mount ID',
                                         element_type=int,
                                         optional=True),
            requirements.BooleanRequirement(name='all',
                                            description='List files from all mounts',
                                            optional=True),
            requirements.StringRequirement(name='path',
                                           description='List files under a specified path',
                                           optional=True),
            requirements.ListRequirement(name='uid',
                                         description='Filter by owner UID',
                                         element_type=int,
                                         optional=True),
            requirements.BooleanRequirement(name='sort',
                                            description='Sort files by path',
                                            optional=True)
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
    def create_uid_filter(cls, uid_list: List[int] = None) -> Callable[[Any], bool]:
        """Constructs a filter function for owner UIDs.
        Args:
            uid_list: List of UIDs that are acceptable (or None if all are acceptable)
        Returns:
            Function which, when provided a UID, returns True if the UID is to be filtered out
        """
        if uid_list is None:
            uid_list = []
        filter_list = [x for x in uid_list if x is not None]

        if filter_list:

            def filter_func(uid):
                return uid not in filter_list
            
            return filter_func
        else:
            return lambda _: False

    @classmethod
    def _mode_to_str(cls, mode:int) -> str:
        """Calculate the mode string (see http://cvsweb.netbsd.org/bsdweb.cgi/src/lib/libc/string/strmode.c?rev=1.16&content-type=text/x-cvsweb-markup)"""
        string = ''

        # get file type character
        filetype = mode & S_IFMT
        if filetype & S_IFDIR:
            string += 'd'
        elif filetype & S_IFCHR:
            string += 'c'
        elif filetype & S_IFBLK:
            string += 'b'
        elif filetype & S_IFREG:
            string += '-'
        elif filetype & S_IFLNK:
            string += 'l'
        elif filetype & S_IFSOCK:
            string += 's'
        elif filetype & S_IFIFO:
            string += 'p'
        else:
            string += '?'
        
        # get user permissions
        string += 'r' if mode & S_IRUSR else '-'
        string += 'w' if mode & S_IWUSR else '-'
        user_execute = mode & (S_IXUSR | S_ISUID)
        if user_execute == 0:
            string += '-'
        elif user_execute == S_IXUSR:
            string += 'x'
        elif user_execute == S_ISUID:
            string += 'S'
        elif user_execute == S_IXUSR | S_ISUID:
            string += 's'
        
        # get group permissions
        string += 'r' if mode & S_IRGRP else '-'
        string += 'w' if mode & S_IWGRP else '-'
        group_execute = mode & (S_IXGRP | S_ISGID)
        if group_execute == 0:
            string += '-'
        elif group_execute == S_IXGRP:
            string += 'x'
        elif group_execute == S_ISGID:
            string += 'S'
        elif group_execute == S_IXGRP | S_ISGID:
            string += 's'

        # get other permissions
        string += 'r' if mode & S_IROTH else '-'
        string += 'w' if mode & S_IWOTH else '-'
        other_execute = mode & (S_IXOTH | S_ISVTX)
        if other_execute == 0:
            string += '-'
        elif other_execute == S_IXOTH:
            string += 'x'
        elif other_execute == S_ISVTX:
            string += 'T'
        elif other_execute == S_IXOTH | S_ISVTX:
            string += 't'

        return string

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
            inode = dentry.d_inode.dereference()
        # bad inode
        except exceptions.PagedInvalidAddressException:
            inode_id = -1
            inode_addr = 0
            inode = None
        
        # get file info
        mode = ''
        uid = -1
        gid = -1
        size = -1
        if inode is not None:
            # get mode
            mode = cls._mode_to_str(inode.i_mode)

            # get uid and gid
            uid = inode.i_uid.val
            gid = inode.i_gid.val

            # get size
            size = inode.i_size

        return mnt_id, inode_id, inode_addr, mode, uid, gid, size, path
    
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
                     mnt_filter: Callable[[Any], bool] = lambda _: False,
                     all:bool = False) -> Tuple[symbols.linux.extensions.mount, List[symbols.linux.extensions.dentry]]:
        """Get a list of all cached dentries in the filesystem that match the given filters."""
        # make sure pid_filter and all aren't used together
        if all and pid_filter is not None:
            raise ValueError('all option cannot be used with a PID filter')

        vmlinux = context.modules[vmlinux_module_name]

        # list of dentries
        dentries = []

        # get a list of mounts to use
        if not all and pid_filter is None:
            pid_filter = pslist.PsList.create_pid_filter([1])

        if all:
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
        uid_filter = self.create_uid_filter(self.config.get('uid', None))
        pids = self.config.get('pid', None)
        if pids:
            pid_filter = pslist.PsList.create_pid_filter(pids)
        else:
            pid_filter = None
        all = self.config.get('all', False)
        if self.config.get('mount') and not pids:
            all = True

        files = dict()
        dentries = self.get_dentries(context=self.context,
                                     vmlinux_module_name=self.config['kernel'],
                                     pid_filter=pid_filter,
                                     mnt_filter=self.create_mount_filter(self.config.get('mount', None)),
                                     all=all)
        num_dentries = len(dentries)
        for i, (mount, dentry) in enumerate(dentries):
            # print info message every 1000 files
            if i % 1000 == 0:
                vollog.info(f'[{i}/{num_dentries}]  extracting file info and filtering paths')

            info = self.get_file_info(mount, dentry)
            # info could not be extracted
            if info is None:
                continue
            mnt_id, inode_id, inode_addr, mode, uid, gid, size, file_path = info

            # path is not filtered out
            if not path_filter(file_path) and not uid_filter(uid):
                files[file_path] = mnt_id, inode_id, inode_addr, mode, uid, gid, size, file_path
        
        paths = list(files.keys())
        if self.config.get('sort', None):
            vollog.info('sorting files')
            paths.sort()
            vollog.info('done sorting')
        for path in paths:
            mnt_id, inode_id, inode_addr, mode, uid, gid, size, file_path = files[path]
            yield (0, (mnt_id, inode_id, format_hints.Hex(inode_addr), mode, uid, gid, size, file_path))
    
    def run(self):
        # make sure 'all' and 'pid' aren't used together
        if self.config.get('all') and self.config.get('pid'):
            raise exceptions.PluginRequirementException('"pid" and "all" cannot be used together')

        return renderers.TreeGrid([('Mount ID', int), ('Inode ID', int), ('Inode Address', format_hints.Hex), ('Mode', str), ('UID', int), ('GID', int), ('Size', int), ('File Path', str)], self._generator())
