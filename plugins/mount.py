from typing import List, Tuple
import math
import logging

from volatility3.framework import renderers, interfaces, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework import exceptions
from volatility3.framework.objects import utility


MAX_STRING = 256

# for flag string
MNT_FLAGS = {
    0x1        : "MNT_NOSUID",
    0x2        : "MNT_NODEV",
    0x4        : "MNT_NOEXEC",
    0x8        : "MNT_NOATIME",
    0x10       : "MNT_NODIRATIME",
    0x20       : "MNT_RELATIME",
    0x40       : "MNT_READONLY",
    0x80       : "MNT_NOSYMFOLLOW",
    0x100      : "MNT_SHRINKABLE",
    0x200      : "MNT_WRITE_HOLD",
    0x1000     : "MNT_SHARED",
    0x2000     : "MNT_UNBINDABLE",
    0x4000     : "MNT_INTERNAL",
    0x40000    : "MNT_LOCK_ATIME",
    0x80000    : "MNT_LOCK_NOEXEC",
    0x100000   : "MNT_LOCK_NOSUID",
    0x200000   : "MNT_LOCK_NODEV",
    0x400000   : "MNT_LOCK_READONLY",
    0x800000   : "MNT_LOCKED",
    0x1000000  : "MNT_DOOMED",
    0x2000000  : "MNT_SYNC_UMOUNT",
    0x4000000  : "MNT_MARKED",
    0x8000000  : "MNT_UMOUNT",
    0x10000000 : "MNT_CURSOR"
}

# for determining access
MNT_READONLY = 0x40 # https://elixir.bootlin.com/linux/v5.15-rc4/source/include/linux/mount.h#L32
SB_RDONLY    = 0x1  # https://elixir.bootlin.com/linux/v5.15-rc4/source/include/linux/fs.h#L1394


vollog = logging.getLogger(__name__)


class Mount(interfaces.plugins.PluginInterface):
    """Lists all mounted filesystems."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.ModuleRequirement(name='kernel',
                                            description='Linux kernel',
                                            architectures=['Intel32', 'Intel64'])]
    
    @classmethod
    def get_mount_points(cls,
                        context: interfaces.context.ContextInterface,
                        vmlinux_module_name: str) -> List[symbols.linux.extensions.mount]:
        """Extract a list of all mounts."""
        vmlinux = context.modules[vmlinux_module_name]
        kernel = context.modules[vmlinux_module_name]
        layer = context.layers[kernel.layer_name]

        # kernel >= 3.13.9 uses an hlist_head instead of a list_head
        if vmlinux.has_symbol('set_mphash_entries'):
            mnt_type = 'mount'
            mount_hashtable_type = 'hlist_head'
        # kernel >= 3.3 makes mount_hashtable be a table of struct mount
        elif vmlinux.has_type('mount'):
            mnt_type = 'mount'
            mount_hashtable_type = 'list_head'
        else:
            mnt_type = 'vfsmount'
            mount_hashtable_type = 'list_head'
        
        # in kernel < 3.13.9 mount_hashtable size is predefined
        if mount_hashtable_type == 'list_head':
            list_head_size = vmlinux.get_type('list_head').size
            page_size = layer.page_size
            mount_hashtable_entries = 1 << int(math.log(page_size/list_head_size, 2))
        
        # in kernel >= 3.13.9 mount_hashtable size is determined at boot time
        else:
            try:
                # mhash_entries is initialized from boot parameters during setup
                # and is used to allocate memory for mount_hashtable
                mount_hashtable_entries = vmlinux.object_from_symbol('mhash_entries')
            # sometimes mhash_entries isn't available (it is marked in the linux source
            # as __init_data which means it may be deallocated at some point)
            except exceptions.PagedInvalidAddressException:
                # m_hash_mask is the binary mask of the number of entries
                mount_hashtable_entries = vmlinux.object_from_symbol('m_hash_mask') + 1
        
        vollog.info(f'mount_hashtable entries: {mount_hashtable_entries}')

        mount_hashtable_ptr = vmlinux.object_from_symbol('mount_hashtable')
        mount_hashtable = vmlinux.object(object_type='array',
                                        offset=mount_hashtable_ptr,
                                        subtype=vmlinux.get_type(mount_hashtable_type),
                                        count=mount_hashtable_entries,
                                        absolute=True)

        # list of all mounts
        mounts = list()

        # iterate through mount_hashtable
        for hash in mount_hashtable:
            # list_head - pointer to first mount is in 'next'
            if mount_hashtable_type == 'list_head':
                if not hash.next:
                    continue
                first_mount = hash.next.dereference().cast(mnt_type)
            # hlist_head - pointer to first mount is in 'first'
            elif mount_hashtable_type == 'hlist_head':
                if not hash.first:
                    continue
                first_mount = hash.first.dereference().cast(mnt_type)

            # walk linked list of mounts
            for mount in first_mount.mnt_hash:
                mounts.append(mount)

        vollog.info(f'total mounts: {len(mounts)}')

        return mounts

    @classmethod
    def get_effective_mount_points(cls,
                        context: interfaces.context.ContextInterface,
                        vmlinux_module_name: str) -> List[symbols.linux.extensions.mount]:
        """
        Extract a list of "effective" mount points.
        When extracting all mounts, multiple mounts can point to the same superblock.
        Because the superblock represents an instance of a file system,
        Only a single mount for each superblock is relevant.
        The mount with the lowest ID is considered "effective".
        """
        # get all mounts
        all_mounts = cls.get_mount_points(context, vmlinux_module_name)

        # dictionary indexed by superblock with value mount with lowest ID that points to it
        superblocks = dict()

        # iterate through all mounts
        for mount in all_mounts:
            # get devname
            devname = utility.pointer_to_string(mount.mnt_devname, MAX_STRING)

            # ignore devtmpfs - it has the lowest ID for the superblock of type devtmpfs,
            # but the effective mount for this superblock (as listed by the mount command) is udev
            if devname == 'devtmpfs':
                continue

            sb = mount.get_mnt_sb()

            # superblock not in dict
            if sb not in superblocks:
                superblocks[sb] = mount
            
            # ID is lower than lowest ID for this superblock
            elif mount.mnt_id < superblocks[sb].mnt_id:
                superblocks[sb] = mount
        
        # build list of effective mounts
        effective_mounts = [mount for mount in superblocks.values()]
        return effective_mounts

    @classmethod
    def parse_mount(cls, mount: symbols.linux.extensions.mount) -> Tuple[int, str, str, str, str, str]:
        """
        Parse a mount and return the following tuple:
        id, devname, path, fstype, access, flags
        """
        # get id
        id = mount.mnt_id

        # get devname
        devname = utility.pointer_to_string(mount.mnt_devname, MAX_STRING)

        # get path
        sb = mount.get_mnt_sb().dereference()
        s_root = sb.s_root.dereference()
        mnt_parent = mount.mnt_parent.dereference()
        mnt_root = mount.get_mnt_root().dereference()
        path = symbols.linux.LinuxUtilities._do_get_path(s_root, mnt_parent, mnt_root, mount)

        # get fs type
        fs_type = utility.pointer_to_string(mount.get_mnt_sb().dereference().s_type.dereference().name, MAX_STRING)

        # get access
        mnt_flags = mount.get_mnt_flags()
        sb_flags = sb.s_flags
        if mnt_flags & MNT_READONLY or sb_flags & SB_RDONLY:
            access = 'RO'
        else:
            access = 'RW'

        # build string of flags
        flags = list()
        for bit_location in range(mnt_flags.vol.size * 8):
            # bit is set
            flag = mnt_flags & (1 << bit_location)
            if flag:
                # try getting flag string
                try:
                    flags.append(MNT_FLAGS[flag])
                except KeyError:
                    flags.append(f'FLAG_{hex(flag)}')
        
        return id, devname, path, fs_type, access, ','.join(flags)

    def _generator(self):
        mounts = dict()
        for mount in self.get_effective_mount_points(self.context, self.config['kernel']):
            id, devname, path, fstype, access, flags = self.parse_mount(mount)
            mounts[id] = (id, devname, path, fstype, access, flags)
        
        sorted_ids = list(mounts.keys())
        sorted_ids.sort()
        for id in sorted_ids:
            yield (0, mounts[id])
    
    def run(self):
        return renderers.TreeGrid([('ID', int), ('Devname', str), ('Path', str), ('FS Type', str), ('Access', str), ('Flags', str)], self._generator())
