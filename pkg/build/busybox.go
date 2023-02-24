// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package build

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	apkfs "chainguard.dev/apko/pkg/apk/impl/fs"
)

// /bin/busybox --list-full | sort | sed 's|^|/|g'
var (
	busyboxList = `
	/bin/arch
	/bin/ash
	/bin/base64
	/bin/bbconfig
	/bin/cat
	/bin/chattr
	/bin/chgrp
	/bin/chmod
	/bin/chown
	/bin/cp
	/bin/date
	/bin/dd
	/bin/df
	/bin/dmesg
	/bin/dnsdomainname
	/bin/dumpkmap
	/bin/echo
	/bin/ed
	/bin/egrep
	/bin/false
	/bin/fatattr
	/bin/fdflush
	/bin/fgrep
	/bin/fsync
	/bin/getopt
	/bin/grep
	/bin/gunzip
	/bin/gzip
	/bin/hostname
	/bin/ionice
	/bin/iostat
	/bin/ipcalc
	/bin/kbd_mode
	/bin/kill
	/bin/link
	/bin/linux32
	/bin/linux64
	/bin/ln
	/bin/login
	/bin/ls
	/bin/lsattr
	/bin/lzop
	/bin/makemime
	/bin/mkdir
	/bin/mknod
	/bin/mktemp
	/bin/more
	/bin/mount
	/bin/mountpoint
	/bin/mpstat
	/bin/mv
	/bin/netstat
	/bin/nice
	/bin/pidof
	/bin/ping
	/bin/ping6
	/bin/pipe_progress
	/bin/printenv
	/bin/ps
	/bin/pwd
	/bin/reformime
	/bin/rev
	/bin/rm
	/bin/rmdir
	/bin/run-parts
	/bin/sed
	/bin/setpriv
	/bin/setserial
	/bin/sh
	/bin/sleep
	/bin/stat
	/bin/stty
	/bin/su
	/bin/sync
	/bin/tar
	/bin/touch
	/bin/true
	/bin/umount
	/bin/uname
	/bin/usleep
	/bin/watch
	/bin/zcat
	/sbin/acpid
	/sbin/adjtimex
	/sbin/arp
	/sbin/blkid
	/sbin/blockdev
	/sbin/depmod
	/sbin/fbsplash
	/sbin/fdisk
	/sbin/findfs
	/sbin/fsck
	/sbin/fstrim
	/sbin/getty
	/sbin/halt
	/sbin/hwclock
	/sbin/ifconfig
	/sbin/ifdown
	/sbin/ifenslave
	/sbin/ifup
	/sbin/init
	/sbin/inotifyd
	/sbin/insmod
	/sbin/ip
	/sbin/ipaddr
	/sbin/iplink
	/sbin/ipneigh
	/sbin/iproute
	/sbin/iprule
	/sbin/iptunnel
	/sbin/klogd
	/sbin/loadkmap
	/sbin/logread
	/sbin/losetup
	/sbin/lsmod
	/sbin/mdev
	/sbin/mkdosfs
	/sbin/mkfs.vfat
	/sbin/mkswap
	/sbin/modinfo
	/sbin/modprobe
	/sbin/nameif
	/sbin/nologin
	/sbin/pivot_root
	/sbin/poweroff
	/sbin/raidautorun
	/sbin/reboot
	/sbin/rmmod
	/sbin/route
	/sbin/setconsole
	/sbin/slattach
	/sbin/swapoff
	/sbin/swapon
	/sbin/switch_root
	/sbin/sysctl
	/sbin/syslogd
	/sbin/tunctl
	/sbin/udhcpc
	/sbin/vconfig
	/sbin/watchdog
	/usr/bin/[
	/usr/bin/[[
	/usr/bin/awk
	/usr/bin/basename
	/usr/bin/bc
	/usr/bin/beep
	/usr/bin/blkdiscard
	/usr/bin/bunzip2
	/usr/bin/bzcat
	/usr/bin/bzip2
	/usr/bin/cal
	/usr/bin/chvt
	/usr/bin/cksum
	/usr/bin/clear
	/usr/bin/cmp
	/usr/bin/comm
	/usr/bin/cpio
	/usr/bin/crontab
	/usr/bin/cryptpw
	/usr/bin/cut
	/usr/bin/dc
	/usr/bin/deallocvt
	/usr/bin/diff
	/usr/bin/dirname
	/usr/bin/dos2unix
	/usr/bin/du
	/usr/bin/eject
	/usr/bin/env
	/usr/bin/expand
	/usr/bin/expr
	/usr/bin/factor
	/usr/bin/fallocate
	/usr/bin/find
	/usr/bin/flock
	/usr/bin/fold
	/usr/bin/free
	/usr/bin/fuser
	/usr/bin/groups
	/usr/bin/hd
	/usr/bin/head
	/usr/bin/hexdump
	/usr/bin/hostid
	/usr/bin/id
	/usr/bin/install
	/usr/bin/ipcrm
	/usr/bin/ipcs
	/usr/bin/killall
	/usr/bin/last
	/usr/bin/less
	/usr/bin/logger
	/usr/bin/lsof
	/usr/bin/lsusb
	/usr/bin/lzcat
	/usr/bin/lzma
	/usr/bin/lzopcat
	/usr/bin/md5sum
	/usr/bin/mesg
	/usr/bin/microcom
	/usr/bin/mkfifo
	/usr/bin/mkpasswd
	/usr/bin/nc
	/usr/bin/nl
	/usr/bin/nmeter
	/usr/bin/nohup
	/usr/bin/nproc
	/usr/bin/nsenter
	/usr/bin/nslookup
	/usr/bin/od
	/usr/bin/openvt
	/usr/bin/passwd
	/usr/bin/paste
	/usr/bin/pgrep
	/usr/bin/pkill
	/usr/bin/pmap
	/usr/bin/printf
	/usr/bin/pscan
	/usr/bin/pstree
	/usr/bin/pwdx
	/usr/bin/readlink
	/usr/bin/realpath
	/usr/bin/renice
	/usr/bin/reset
	/usr/bin/resize
	/usr/bin/seq
	/usr/bin/setkeycodes
	/usr/bin/setsid
	/usr/bin/sha1sum
	/usr/bin/sha256sum
	/usr/bin/sha3sum
	/usr/bin/sha512sum
	/usr/bin/showkey
	/usr/bin/shred
	/usr/bin/shuf
	/usr/bin/sort
	/usr/bin/split
	/usr/bin/strings
	/usr/bin/sum
	/usr/bin/tac
	/usr/bin/tail
	/usr/bin/tee
	/usr/bin/test
	/usr/bin/time
	/usr/bin/timeout
	/usr/bin/top
	/usr/bin/tr
	/usr/bin/traceroute
	/usr/bin/traceroute6
	/usr/bin/truncate
	/usr/bin/tty
	/usr/bin/ttysize
	/usr/bin/udhcpc6
	/usr/bin/unexpand
	/usr/bin/uniq
	/usr/bin/unix2dos
	/usr/bin/unlink
	/usr/bin/unlzma
	/usr/bin/unlzop
	/usr/bin/unshare
	/usr/bin/unxz
	/usr/bin/unzip
	/usr/bin/uptime
	/usr/bin/uudecode
	/usr/bin/uuencode
	/usr/bin/vi
	/usr/bin/vlock
	/usr/bin/volname
	/usr/bin/wc
	/usr/bin/wget
	/usr/bin/which
	/usr/bin/who
	/usr/bin/whoami
	/usr/bin/whois
	/usr/bin/xargs
	/usr/bin/xxd
	/usr/bin/xzcat
	/usr/bin/yes
	/usr/sbin/add-shell
	/usr/sbin/addgroup
	/usr/sbin/adduser
	/usr/sbin/arping
	/usr/sbin/brctl
	/usr/sbin/chpasswd
	/usr/sbin/chroot
	/usr/sbin/crond
	/usr/sbin/delgroup
	/usr/sbin/deluser
	/usr/sbin/ether-wake
	/usr/sbin/fbset
	/usr/sbin/killall5
	/usr/sbin/loadfont
	/usr/sbin/nanddump
	/usr/sbin/nandwrite
	/usr/sbin/nbd-client
	/usr/sbin/ntpd
	/usr/sbin/partprobe
	/usr/sbin/rdate
	/usr/sbin/rdev
	/usr/sbin/readahead
	/usr/sbin/remove-shell
	/usr/sbin/rfkill
	/usr/sbin/sendmail
	/usr/sbin/setfont
	/usr/sbin/setlogcons
	`

	busyboxLinks = strings.Fields(busyboxList)
)

func (di *defaultBuildImplementation) InstallBusyboxLinks(fsys apkfs.FullFS) error {
	// does busybox exist? if not, do not bother with symlinks
	if _, err := fsys.Stat("/bin/busybox"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	for _, link := range busyboxLinks {
		dir := filepath.Dir(link)
		if err := fsys.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
		if err := fsys.Symlink("/bin/busybox", link); err != nil {
			return fmt.Errorf("creating busybox link %s: %w", link, err)
		}
	}
	return nil
}
