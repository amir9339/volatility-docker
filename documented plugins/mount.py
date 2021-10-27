# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.plugins.linux.flags as linux_flags
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist


class linux_mount(linux_common.AbstractLinuxCommand):
    """Gather mounted fs/devices"""

    def _parse_mnt(self, mnt, ns, fs_types):
        ret = None

        # invalid root dentry
        if not mnt.mnt_root.is_valid():
            return ret

        # get mount name
        dev_name = mnt.mnt_devname.dereference_as(
            "String", length=linux_common.MAX_STRING_LENGTH)
        # name validation
        if not dev_name.is_valid():
            return ret

        if len(dev_name) < 3:
            return ret

        new_name = False

        # check the first 3 characters of the name
        for nn in str(dev_name)[:3]:
            # I consider this code as obfuscated
            n = ord(nn)
            # non-printable character or '?' character
            if n < 32 or n > 126 or n == 63:  # 63 = ?
                new_name = True
                break

        # the first rule of programming is: DO NOT COMPARE BOOLEANS TO TRUE!!!
        if new_name == True:
            # basically what this does is that if the name was invalid, try extracting the name from a field that is 16 bytes further into the struct.
            # I have absolutely no idea what this field is supposed to be
            s = obj.Object(
                "Pointer", offset=mnt.mnt_devname.obj_offset + 16, vm=self.addr_space)
            if not s.is_valid():
                return ret

            dev_name = s.dereference_as(
                "String", length=linux_common.MAX_STRING_LENGTH)
            if not dev_name.is_valid() or len(dev_name) < 3:
                return ret

            for nn in str(dev_name)[:3]:
                n = ord(nn)
                if n < 32 or n > 126 or n == 63:  # 63 = ?
                    return ret

        # get the mount's superblock's filesystem type's name (that was a mouthful)
        fstype = mnt.mnt_sb.s_type.name.dereference_as(
            "String", length=linux_common.MAX_STRING_LENGTH)

        # bad filesystem type name
        if not fstype.is_valid() or len(fstype) < 3:
            return ret

        for nn in str(fstype)[:3]:
            n = ord(nn)
            if n < 32 or n > 126 or n == 63:  # 63 = ?
                return ret

        # get the full vfs path
        path = linux_common.do_get_path(
            mnt.mnt_sb.s_root, mnt.mnt_parent, mnt.mnt_root, mnt)
        # bad path
        if path == [] or len(path) > 4096:
            return ret

        # get string of mount attributes
        mnt_string = self._calc_mnt_string(mnt)

        # f**ing great documentation here.
        # apparently these flags specify access type
        if (mnt.mnt_flags & 0x40) or (mnt.mnt_sb.s_flags & 0x1):
            rr = "ro"
        else:
            rr = "rw"

        # return superblock, mount name, mount path, filesystem type name, access type, mount attributes
        return mnt.mnt_sb, str(dev_name), path, fstype, rr, mnt_string

    def calculate(self):
        """
        This function is a huge mess and understanding it cost me at least 2 years of my life.
        Here's the TL;DR:
        The "mount_hashtable" symbol is a pointer to an array of linked lists (most are empty).
        These linked lists are of mount structures.
        Walk all of these linked lists and build up a list of mount struct addresses.
        Afterwards, for each mount found, walk 2 other linked lists of mounts which are pointed to by the mount (mnt_child, mnt_list) and add the newly found mounts to the master list of mounts.
        Also, check the parent mount and parent's parent mount to see if they are new.
        Finally, yield some of the info of each mount (except for mounts called devtmpfs), while making sure we don't yield more than 1 mount which belongs to a certain superblock.
        """
        linux_common.set_plugin_members(self)
        # get pointer to mount_hashtable
        mntptr = obj.Object("Pointer", offset=self.addr_space.profile.get_symbol(
            "mount_hashtable"), vm=self.addr_space)
        # convert mount_hashtable to list_head array
        mnt_list = obj.Object(theType="Array", offset=mntptr,
                              vm=self.addr_space, targetType="list_head", count=8200)

        # older kernel versions have 'vfsmount' instead of 'mount'
        if self.profile.has_type("mount"):
            mnttype = "mount"
        else:
            mnttype = "vfsmount"

        ns = None

        # get filesystem types
        fs_types = self._get_filesystem_types()

        hash_mnts = {}  # dictionary of mount object as key (WTF??)
        seen_outer = {}
        # iterate through mount_hashtable arrray
        for (idx, outerlist) in enumerate(mnt_list):
            # empty entry
            if outerlist == None or outerlist.next == None:
                continue

            # we've seen this pointer
            if outerlist.next.v() in seen_outer:
                continue

            # mark pointer as seen
            seen_outer[outerlist.next.v()] = 1

            # bad pointer
            if outerlist == outerlist.next or not outerlist.m("next").is_valid():
                continue

            seen = {}
            mseen = {}
            # walk linked list of mounts
            for mnt in outerlist.list_of_type(mnttype, "mnt_hash"):
                # we've been here (circular list)
                if mnt.v() in seen:
                    break

                # mark node as seen
                seen[mnt.v()] = 1

                # too many nodes
                if len(seen.keys()) > 1024:
                    break

                if mnt.is_valid():
                    # node address
                    mkey = mnt.v()
                    # we haven't seen this node yet (we checked this already WTF??)
                    if not mkey in mseen:
                        hash_mnts[mnt] = 1
                        # mark as seen (AGAIN?!)
                        mseen[mkey] = 1
                else:
                    break
                # TL;DR if parent exists add it to list
                if mnt.mnt_parent.is_valid():
                    mkey = mnt.mnt_parent.v()
                    if not mkey in mseen:
                        hash_mnts[mnt.mnt_parent] = 1
                        mseen[mkey] = 1

                # TL;DR if parent's parent exists add it to list
                # (what about parent's parent's parent :O )
                # seriously this code is ridiculous
                if mnt.mnt_parent.mnt_parent.is_valid():
                    mkey = mnt.mnt_parent.mnt_parent.v()
                    if not mkey in mseen:
                        hash_mnts[mnt.mnt_parent.mnt_parent] = 1
                        mseen[mkey] = 1

        child_mnts = {}
        # iterate through all seen mount objects
        for mnt in hash_mnts:
            cseen = {}
            # walk linked list of children mounts
            for child_mnt in mnt.mnt_child.list_of_type(mnttype, "mnt_child"):

                # invalid child
                if not child_mnt.is_valid():
                    break

                # add child to list (why TF is this a dict)
                child_mnts[child_mnt] = 1

                # we've seen this node
                if child_mnt.v() in cseen:
                    break

                # too many nodes
                if len(child_mnts.keys()) > 1024:
                    break

                # mark node as seen
                cseen[child_mnt.v()] = 1

                # add parent to child list (WHY???)
                if child_mnt.mnt_parent.is_valid():
                    child_mnts[child_mnt.mnt_parent] = 1

                # you guessed it - parent's parent ;)
                if child_mnt.mnt_parent.mnt_parent.is_valid():
                    child_mnts[child_mnt.mnt_parent.mnt_parent] = 1

        # all mounts seen so far
        tmp_mnts = list(set(hash_mnts.keys() + child_mnts.keys()))
        # valid mounts (only name is validated)
        all_mnts = []

        # iterate through seen mounts
        for t in tmp_mnts:
            # mount name (great variable naming, as usual)
            tt = t.mnt_devname.dereference_as(
                "String", length=linux_common.MAX_STRING_LENGTH)
            # name validation
            if tt:
                if len(str(tt)) > 2 or (len(str(tt)) > 1 and str(tt)[0] == '/'):
                    # add to list of valid mounts
                    all_mnts.append(t)

        list_mnts = {}
        seen_m = {}
        # iterate through valid mounts
        for mnt in all_mnts:
            # we've seen this mount
            if mnt.v() in seen_m:
                continue
            else:
                # mark this mount as seen
                seen_m[mnt.v()] = 1

            # walk mnt_list linked list of mounts
            for (idx, child_mnt) in enumerate(mnt.mnt_list.list_of_type(mnttype, "mnt_list")):
                # more than 20 nodes
                if idx > 20:
                    break

                # add to yet another list of mounts
                if child_mnt.is_valid():
                    list_mnts[child_mnt] = 1

                # add parent to list
                if child_mnt.mnt_parent.is_valid():
                    list_mnts[child_mnt.mnt_parent] = 1

                # you know what it is
                if child_mnt.mnt_parent.mnt_parent.is_valid():
                    list_mnts[child_mnt.mnt_parent.mnt_parent] = 1

        # append the new found mounts to the list of all valid mounts
        all_mnts = list(set(all_mnts + list_mnts.keys()))

        # I don't feel so good...
        seen = {}
        # iterate through mounts yet again
        for (idx, mnt) in enumerate(all_mnts):
            # we haven't seen this superblock
            if mnt.mnt_sb.v() not in seen:
                # get all kinds of info about this mount
                ret = self._parse_mnt(mnt, ns, fs_types)

                mark = False

                # unpack the info
                if ret:
                    (mnt_sb, dev_name, path, fstype, rr, mnt_string) = ret

                    # ignore 'devtmpfs' that is mounted on '/'
                    if not (dev_name == "devtmpfs" and path == "/"):
                        # yield the info
                        yield (mnt_sb, dev_name, path, fstype, rr, mnt_string)
                        mark = True

                # mark this superblock as seen only if we didn't ignore this mount
                if mark:
                    seen[mnt.mnt_sb.v()] = 1

    def _calc_mnt_string(self, mnt):
        # build string of mount attributes
        ret = ""

        for mflag in linux_flags.mnt_flags:
            if mflag & mnt.mnt_flags:
                ret = ret + linux_flags.mnt_flags[mflag]

        return ret

    def _get_filesystem_types(self):
        all_fs = {}

        # get linked list of filesystem types from symbol 'file_systems'
        fs_ptr = obj.Object("Pointer", offset=self.addr_space.profile.get_symbol(
            "file_systems"), vm=self.addr_space)
        file_systems = fs_ptr.dereference_as("file_system_type")

        fs = file_systems

        # walk the linked list of filesystem types
        while fs.is_valid():
            # get the fs type name
            fsname = obj.Object("String", offset=fs.name,
                                vm=self.addr_space, length=256)
            # add the fs type to a dict
            all_fs[str(fsname)] = fs
            fs = fs.next

        return all_fs

    def render_text(self, outfd, data):
        for (_sb, dev_name, path, fstype, rr, mnt_string) in data:
            outfd.write("{0:25s} {1:35s} {2:12s} {3:2s}{4:64s}\n".format(
                dev_name, path, fstype, rr, mnt_string))
