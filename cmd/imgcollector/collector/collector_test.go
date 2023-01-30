package collector

import (
	"context"
	"os"
	"path"
	"testing"
	"time"

	"github.com/castai/kvisor/blobscache"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	mock_blobcache "github.com/castai/kvisor/blobscache/mock"
	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/cmd/imgcollector/config"
	"github.com/castai/kvisor/cmd/imgcollector/image/hostfs"
)

func TestWithRealCache(t *testing.T) {
	imgName := "notused"
	imgID := "public.ecr.aws/docker/library/redis@sha256:dc1b954f5a1db78e31b8870966294d2f93fa8a7fba5c1337a1ce4ec55f311bc3"

	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	client := &mockClient{}
	realCache := blobscache.NewBlobsCacheServer(log, blobscache.ServerConfig{
		ServePort: 6969,
	})
	go realCache.Start(context.Background())

	realCacheClient := blobscache.NewRemoteBlobsCache("http://127.0.0.1:6969")

	cwd, _ := os.Getwd()
	p := path.Join(cwd, "..", "image/hostfs/testdata/redis/io.containerd.content.v1.content")

	c := New(log, config.Config{
		ImageID:   imgID,
		ImageName: imgName,
		Timeout:   5 * time.Minute,
		Mode:      config.ModeHostFS,
		Runtime:   config.RuntimeContainerd,
	}, client, realCacheClient, &hostfs.ContainerdHostFSConfig{
		Platform: v1.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		ContentDir: p,
	})

	// cache miss and hit
	for i := 0; i <= 2; i++ {
		r.NoError(c.Collect(ctx))
	}
}

func TestCollector(t *testing.T) {
	t.Run("sends metadata", func(t *testing.T) {
		imgName := "notused"
		imgID := "gke.gcr.io/phpmyadmin@sha256:1ff6c18fbef2045af6b9c16bf034cc421a29027b800e4f9b68ae9b1cb3e9ae07"

		r := require.New(t)
		ctx := context.Background()
		log := logrus.New()
		log.SetLevel(logrus.DebugLevel)

		client := &mockClient{}
		mockCache := mock_blobcache.MockClient{}

		cwd, _ := os.Getwd()
		p := path.Join(cwd, "..", "image/hostfs/testdata/amd64-linux/io.containerd.content.v1.content")

		c := New(log, config.Config{
			ImageID:   imgID,
			ImageName: imgName,
			Timeout:   5 * time.Minute,
			Mode:      config.ModeHostFS,
			Runtime:   config.RuntimeContainerd,
		}, client, mockCache, &hostfs.ContainerdHostFSConfig{
			Platform: v1.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			ContentDir: p,
		})

		r.NoError(c.Collect(ctx))
	})

	t.Run("find image manifest from config digest", func(t *testing.T) {
		imgName := "notused"
		imgID := "public.ecr.aws/docker/library/redis@sha256:9192ed4e495547641a71f90d7738578d4e9d05212e7d55d02cfc7f0e1198a61e"

		r := require.New(t)
		ctx := context.Background()
		log := logrus.New()
		log.SetLevel(logrus.DebugLevel)

		client := &mockClient{}
		mockCache := mock_blobcache.MockClient{}

		cwd, _ := os.Getwd()
		p := path.Join(cwd, "..", "image/hostfs/testdata/redis/io.containerd.content.v1.content")

		c := New(log, config.Config{
			ImageID:   imgID,
			ImageName: imgName,
			Timeout:   5 * time.Minute,
			Mode:      config.ModeHostFS,
			Runtime:   config.RuntimeContainerd,
		}, client, mockCache, &hostfs.ContainerdHostFSConfig{
			Platform: v1.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			ContentDir: p,
		})

		r.NoError(c.Collect(ctx))
	})

	t.Run("collects binaries", func(t *testing.T) {
		imgName := "notused"
		imgID := "gke.gcr.io/phpmyadmin@sha256:b0d9c54760b35edd1854e5710c1a62a28ad2d2b070c801da3e30a3e59c19e7e3"

		r := require.New(t)
		ctx := context.Background()
		log := logrus.New()
		log.SetLevel(logrus.DebugLevel)

		client := &mockClient{}
		mockCache := mock_blobcache.MockClient{}

		cwd, _ := os.Getwd()
		p := path.Join(cwd, "..", "image/hostfs/testdata/amd64-linux/io.containerd.content.v1.content")

		c := New(log, config.Config{
			ImageID:   imgID,
			ImageName: imgName,
			Timeout:   5 * time.Minute,
			Mode:      config.ModeHostFS,
			Runtime:   config.RuntimeContainerd,
		}, client, mockCache, &hostfs.ContainerdHostFSConfig{
			Platform: v1.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			ContentDir: p,
		})

		r.NoError(c.Collect(ctx))
		r.Equal(map[string][]string{
			"acl":     {"/bin/chacl", "/bin/getfacl", "/bin/setfacl"},
			"adduser": {"/usr/sbin/adduser", "/usr/sbin/deluser", "/usr/sbin/addgroup", "/usr/sbin/delgroup"},
			"apt": {
				"/usr/bin/apt", "/usr/bin/apt-cache", "/usr/bin/apt-cdrom", "/usr/bin/apt-config", "/usr/bin/apt-get",
				"/usr/bin/apt-key", "/usr/bin/apt-mark",
			},
			"base-passwd":     {"/usr/sbin/update-passwd"},
			"bash":            {"/bin/bash", "/usr/bin/bashbug", "/usr/bin/clear_console", "/bin/rbash"},
			"bsdutils":        {"/usr/bin/logger", "/usr/bin/renice", "/usr/bin/script", "/usr/bin/scriptlive", "/usr/bin/scriptreplay", "/usr/bin/wall"},
			"ca-certificates": {"/usr/sbin/update-ca-certificates"},
			"coreutils": {
				"/bin/cat", "/bin/chgrp", "/bin/chmod", "/bin/chown", "/bin/cp", "/bin/date", "/bin/dd", "/bin/df", "/bin/dir",
				"/bin/echo", "/bin/false", "/bin/ln", "/bin/ls", "/bin/mkdir", "/bin/mknod", "/bin/mktemp", "/bin/mv", "/bin/pwd",
				"/bin/readlink", "/bin/rm", "/bin/rmdir", "/bin/sleep", "/bin/stty", "/bin/sync", "/bin/touch", "/bin/true",
				"/bin/uname", "/bin/vdir", "/usr/bin/[", "/usr/bin/arch", "/usr/bin/b2sum", "/usr/bin/base32", "/usr/bin/base64",
				"/usr/bin/basename", "/usr/bin/basenc", "/usr/bin/chcon", "/usr/bin/cksum", "/usr/bin/comm", "/usr/bin/csplit",
				"/usr/bin/cut", "/usr/bin/dircolors", "/usr/bin/dirname", "/usr/bin/du", "/usr/bin/env", "/usr/bin/expand",
				"/usr/bin/expr", "/usr/bin/factor", "/usr/bin/fmt", "/usr/bin/fold", "/usr/bin/groups", "/usr/bin/head",
				"/usr/bin/hostid", "/usr/bin/id", "/usr/bin/install", "/usr/bin/join", "/usr/bin/link", "/usr/bin/logname",
				"/usr/bin/md5sum", "/usr/bin/mkfifo", "/usr/bin/nice", "/usr/bin/nl", "/usr/bin/nohup", "/usr/bin/nproc",
				"/usr/bin/numfmt", "/usr/bin/od", "/usr/bin/paste", "/usr/bin/pathchk", "/usr/bin/pinky", "/usr/bin/pr",
				"/usr/bin/printenv", "/usr/bin/printf", "/usr/bin/ptx", "/usr/bin/realpath", "/usr/bin/runcon", "/usr/bin/seq",
				"/usr/bin/sha1sum", "/usr/bin/sha224sum", "/usr/bin/sha256sum", "/usr/bin/sha384sum", "/usr/bin/sha512sum",
				"/usr/bin/shred", "/usr/bin/shuf", "/usr/bin/sort", "/usr/bin/split", "/usr/bin/stat", "/usr/bin/stdbuf",
				"/usr/bin/sum", "/usr/bin/tac", "/usr/bin/tail", "/usr/bin/tee", "/usr/bin/test", "/usr/bin/timeout",
				"/usr/bin/tr", "/usr/bin/truncate", "/usr/bin/tsort", "/usr/bin/tty", "/usr/bin/unexpand", "/usr/bin/uniq",
				"/usr/bin/unlink", "/usr/bin/users", "/usr/bin/wc", "/usr/bin/who", "/usr/bin/whoami", "/usr/bin/yes",
				"/usr/sbin/chroot", "/usr/bin/md5sum.textutils",
			},
			"curl": {"/usr/bin/curl"},
			"dash": {"/bin/dash", "/bin/sh"},
			"db-util": {
				"/usr/bin/db_archive", "/usr/bin/db_checkpoint", "/usr/bin/db_deadlock", "/usr/bin/db_dump", "/usr/bin/db_hotbackup",
				"/usr/bin/db_load", "/usr/bin/db_log_verify", "/usr/bin/db_printlog", "/usr/bin/db_recover", "/usr/bin/db_replicate",
				"/usr/bin/db_sql", "/usr/bin/db_stat", "/usr/bin/db_upgrade", "/usr/bin/db_verify",
			},
			"db5.3-util": {
				"/usr/bin/db5.3_archive", "/usr/bin/db5.3_checkpoint", "/usr/bin/db5.3_deadlock", "/usr/bin/db5.3_dump",
				"/usr/bin/db5.3_hotbackup", "/usr/bin/db5.3_load", "/usr/bin/db5.3_log_verify", "/usr/bin/db5.3_printlog",
				"/usr/bin/db5.3_recover", "/usr/bin/db5.3_replicate", "/usr/bin/db5.3_stat", "/usr/bin/db5.3_upgrade",
				"/usr/bin/db5.3_verify",
			},
			"debconf": {
				"/usr/bin/debconf", "/usr/bin/debconf-apt-progress", "/usr/bin/debconf-communicate", "/usr/bin/debconf-copydb",
				"/usr/bin/debconf-escape", "/usr/bin/debconf-set-selections", "/usr/bin/debconf-show", "/usr/sbin/dpkg-preconfigure",
				"/usr/sbin/dpkg-reconfigure",
			},
			"debianutils": {
				"/bin/run-parts", "/bin/tempfile", "/sbin/installkernel", "/usr/bin/ischroot", "/usr/bin/savelog",
				"/usr/bin/which", "/usr/sbin/add-shell", "/usr/sbin/remove-shell",
			},
			"diffutils": {"/usr/bin/cmp", "/usr/bin/diff", "/usr/bin/diff3", "/usr/bin/sdiff"},
			"dpkg": {
				"/sbin/start-stop-daemon", "/usr/bin/dpkg", "/usr/bin/dpkg-deb", "/usr/bin/dpkg-divert", "/usr/bin/dpkg-maintscript-helper",
				"/usr/bin/dpkg-query", "/usr/bin/dpkg-realpath", "/usr/bin/dpkg-split", "/usr/bin/dpkg-statoverride", "/usr/bin/dpkg-trigger",
				"/usr/bin/update-alternatives", "/usr/sbin/dpkg-fsys-usrunmess",
			},
			"findutils": {"/usr/bin/find", "/usr/bin/xargs"},
			"gpgv":      {"/usr/bin/gpgv"},
			"grep":      {"/bin/egrep", "/bin/fgrep", "/bin/grep", "/usr/bin/rgrep"},
			"gzip": {
				"/bin/gunzip", "/bin/gzexe", "/bin/gzip", "/bin/uncompress",
				"/bin/zcat", "/bin/zcmp", "/bin/zdiff", "/bin/zegrep", "/bin/zfgrep",
				"/bin/zforce", "/bin/zgrep", "/bin/zless", "/bin/zmore", "/bin/znew",
			},
			"hostname":            {"/bin/hostname", "/bin/dnsdomainname", "/bin/domainname", "/bin/nisdomainname", "/bin/ypdomainname"},
			"init-system-helpers": {"/usr/bin/deb-systemd-helper", "/usr/bin/deb-systemd-invoke", "/usr/sbin/invoke-rc.d", "/usr/sbin/service", "/usr/sbin/update-rc.d"},
			"insserv":             {"/sbin/insserv"},
			"libc-bin": {
				"/sbin/ldconfig", "/usr/bin/catchsegv", "/usr/bin/getconf", "/usr/bin/getent", "/usr/bin/iconv",
				"/usr/bin/ldd", "/usr/bin/locale", "/usr/bin/localedef", "/usr/bin/pldd", "/usr/bin/tzselect",
				"/usr/bin/zdump", "/usr/sbin/iconvconfig", "/usr/sbin/zic",
			},
			"libpam-modules-bin": {
				"/sbin/mkhomedir_helper", "/sbin/unix_chkpwd", "/sbin/unix_update", "/usr/sbin/faillock", "/usr/sbin/pam_timestamp_check",
			},
			"libpam-runtime": {"/usr/sbin/pam-auth-update", "/usr/sbin/pam_getenv"},
			"login":          {"/bin/login", "/usr/bin/faillog", "/usr/bin/lastlog", "/usr/bin/newgrp", "/usr/sbin/nologin", "/usr/bin/sg"},
			"mawk":           {"/usr/bin/mawk"},
			"mount":          {"/bin/mount", "/bin/umount", "/sbin/losetup", "/sbin/swapoff", "/sbin/swapon"},
			"openssl":        {"/usr/bin/c_rehash", "/usr/bin/openssl"},
			"passwd": {
				"/sbin/shadowconfig", "/usr/bin/chage", "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/expiry", "/usr/bin/gpasswd",
				"/usr/bin/passwd", "/usr/sbin/chgpasswd", "/usr/sbin/chpasswd", "/usr/sbin/cppw", "/usr/sbin/groupadd",
				"/usr/sbin/groupdel", "/usr/sbin/groupmems", "/usr/sbin/groupmod", "/usr/sbin/grpck", "/usr/sbin/grpconv",
				"/usr/sbin/grpunconv", "/usr/sbin/newusers", "/usr/sbin/pwck", "/usr/sbin/pwconv", "/usr/sbin/pwunconv",
				"/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/sbin/usermod", "/usr/sbin/vipw", "/usr/sbin/cpgr", "/usr/sbin/vigr",
			},
			"perl-base": {"/usr/bin/perl", "/usr/bin/perl5.32.1"},
			"procps": {
				"/bin/kill", "/bin/ps", "/sbin/sysctl", "/usr/bin/free", "/usr/bin/pgrep", "/usr/bin/pidwait", "/usr/bin/pmap",
				"/usr/bin/pwdx", "/usr/bin/skill", "/usr/bin/slabtop", "/usr/bin/tload", "/usr/bin/top", "/usr/bin/uptime",
				"/usr/bin/vmstat", "/usr/bin/w", "/usr/bin/watch", "/usr/bin/pkill", "/usr/bin/snice",
			},
			"sasl2-bin": {
				"/usr/bin/gen-auth", "/usr/bin/sasl-sample-client", "/usr/bin/saslfinger", "/usr/sbin/sasl-sample-server",
				"/usr/sbin/saslauthd", "/usr/sbin/sasldbconverter2", "/usr/sbin/sasldblistusers2", "/usr/sbin/saslpasswd2",
				"/usr/sbin/saslpluginviewer", "/usr/sbin/testsaslauthd",
			},
			"sed":            {"/bin/sed"},
			"startpar":       {"/bin/startpar"},
			"sysvinit-utils": {"/sbin/fstab-decode", "/sbin/killall5", "/bin/pidof"},
			"tar":            {"/bin/tar", "/usr/sbin/rmt-tar", "/usr/sbin/tarcat"},
			"tzdata":         {"/usr/sbin/tzconfig"},
			"util-linux": {
				"/bin/dmesg", "/bin/findmnt", "/bin/lsblk", "/bin/more", "/bin/mountpoint", "/bin/su", "/bin/wdctl",
				"/sbin/agetty", "/sbin/blkdiscard", "/sbin/blkid", "/sbin/blkzone", "/sbin/blockdev", "/sbin/chcpu",
				"/sbin/ctrlaltdel", "/sbin/findfs", "/sbin/fsck", "/sbin/fsck.cramfs", "/sbin/fsck.minix", "/sbin/fsfreeze",
				"/sbin/fstrim", "/sbin/hwclock", "/sbin/isosize", "/sbin/mkfs", "/sbin/mkfs.bfs", "/sbin/mkfs.cramfs",
				"/sbin/mkfs.minix", "/sbin/mkswap", "/sbin/pivot_root", "/sbin/raw", "/sbin/runuser", "/sbin/sulogin",
				"/sbin/swaplabel", "/sbin/switch_root", "/sbin/wipefs", "/sbin/zramctl", "/usr/bin/addpart", "/usr/bin/choom",
				"/usr/bin/chrt", "/usr/bin/delpart", "/usr/bin/fallocate", "/usr/bin/fincore", "/usr/bin/flock",
				"/usr/bin/getopt", "/usr/bin/ionice", "/usr/bin/ipcmk", "/usr/bin/ipcrm", "/usr/bin/ipcs", "/usr/bin/last",
				"/usr/bin/lscpu", "/usr/bin/lsipc", "/usr/bin/lslocks", "/usr/bin/lslogins", "/usr/bin/lsmem", "/usr/bin/lsns",
				"/usr/bin/mcookie", "/usr/bin/mesg", "/usr/bin/namei", "/usr/bin/nsenter", "/usr/bin/partx", "/usr/bin/prlimit",
				"/usr/bin/resizepart", "/usr/bin/rev", "/usr/bin/setarch", "/usr/bin/setpriv", "/usr/bin/setsid",
				"/usr/bin/setterm", "/usr/bin/taskset", "/usr/bin/unshare", "/usr/bin/utmpdump", "/usr/bin/whereis",
				"/usr/sbin/chmem", "/usr/sbin/fdformat", "/usr/sbin/ldattach", "/usr/sbin/readprofile", "/usr/sbin/rtcwake",
				"/sbin/getty", "/usr/bin/i386", "/usr/bin/lastb", "/usr/bin/linux32", "/usr/bin/linux64", "/usr/bin/x86_64",
			},
		}, client.meta.InstalledBinaries)
	})
}

type mockClient struct {
	meta *castai.ImageMetadata
}

func (m *mockClient) SendLogs(ctx context.Context, req *castai.LogEvent) error {
	return nil
}

func (m *mockClient) SendCISReport(ctx context.Context, report *castai.KubeBenchReport) error {
	return nil
}

func (m *mockClient) SendDeltaReport(ctx context.Context, report *castai.Delta) error {
	return nil
}

func (m *mockClient) SendLinterChecks(ctx context.Context, checks []castai.LinterCheck) error {
	return nil
}

func (m *mockClient) SendImageMetadata(ctx context.Context, meta *castai.ImageMetadata) error {
	m.meta = meta
	return nil
}

func (m *mockClient) SendCISCloudScanReport(ctx context.Context, report *castai.CloudScanReport) error {
	return nil
}

func (m *mockClient) PostTelemetry(ctx context.Context, initial bool) (*castai.TelemetryResponse, error) {
	return nil, nil
}
