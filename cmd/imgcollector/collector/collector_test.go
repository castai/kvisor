package collector

import (
	"context"
	"os"
	"path"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/golang/mock/gomock"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	mock_blobcache "github.com/castai/sec-agent/blobscache/mock"
	mock_castai "github.com/castai/sec-agent/castai/mock"
	"github.com/castai/sec-agent/cmd/imgcollector/config"
	"github.com/castai/sec-agent/cmd/imgcollector/image/hostfs"
)

func TestCollector(t *testing.T) {
	imgName := "notused"
	imgID := "gke.gcr.io/phpmyadmin@sha256:1ff6c18fbef2045af6b9c16bf034cc421a29027b800e4f9b68ae9b1cb3e9ae07"

	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	ctrl := gomock.NewController(t)
	mockClient := mock_castai.NewMockClient(ctrl)
	mockCache := mock_blobcache.MockClient{}

	cwd, _ := os.Getwd()
	p := path.Join(cwd, "..", "image/hostfs/testdata/amd64-linux/io.containerd.content.v1.content")

	c := New(log, config.Config{
		ImageID:   imgID,
		ImageName: imgName,
		Timeout:   5 * time.Minute,
		Mode:      config.ModeContainerdHostFS,
	}, mockClient, mockCache, &hostfs.ContainerdHostFSConfig{
		Platform: v1.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		ContentDir: p,
	})

	mockClient.EXPECT().SendImageMetadata(gomock.Any(), gomock.Any())
	err := c.Collect(ctx)
	r.NoError(err)
}

func TestInstalledFiles(t *testing.T) {
	imgName := "notused"
	imgID := "gke.gcr.io/phpmyadmin@sha256:b0d9c54760b35edd1854e5710c1a62a28ad2d2b070c801da3e30a3e59c19e7e3"

	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	ctrl := gomock.NewController(t)
	mockClient := mock_castai.NewMockClient(ctrl)
	mockCache := mock_blobcache.MockClient{}

	cwd, _ := os.Getwd()
	p := path.Join(cwd, "..", "image/hostfs/testdata/amd64-linux/io.containerd.content.v1.content")

	c := New(log, config.Config{
		ImageID:   imgID,
		ImageName: imgName,
		Timeout:   5 * time.Minute,
		Mode:      config.ModeContainerdHostFS,
	}, mockClient, mockCache, &hostfs.ContainerdHostFSConfig{
		Platform: v1.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		ContentDir: p,
	})

	arRef, err := c.inspect(ctx)
	r.NoError(err)

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
	}, c.collectInstalledBinaries(arRef))
}

func TestInspect(t *testing.T) {
	imgName := "notused"
	imgID := "gke.gcr.io/phpmyadmin@sha256:1ff6c18fbef2045af6b9c16bf034cc421a29027b800e4f9b68ae9b1cb3e9ae07"

	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	ctrl := gomock.NewController(t)
	mockClient := mock_castai.NewMockClient(ctrl)
	mockCache := mock_blobcache.MockClient{}

	cwd, _ := os.Getwd()
	p := path.Join(cwd, "..", "image/hostfs/testdata/amd64-linux/io.containerd.content.v1.content")

	c := New(log, config.Config{
		ImageID:   imgID,
		ImageName: imgName,
		Timeout:   5 * time.Minute,
		Mode:      config.ModeContainerdHostFS,
	}, mockClient, mockCache, &hostfs.ContainerdHostFSConfig{
		Platform: v1.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		ContentDir: p,
	})

	configCreate, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", "2021-03-16 13:16:57.822648569 +0000 UTC")
	r.NoError(err)

	cfgFile := &v1.ConfigFile{
		Architecture:  "amd64",
		Container:     "",
		Created:       v1.Time{Time: configCreate},
		DockerVersion: "",
		History: []v1.History{
			{
				Created:    v1.Time{Time: configCreate},
				CreatedBy:  "ARG ARCH",
				Comment:    "buildkit.dockerfile.v0",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: configCreate},
				CreatedBy:  "ADD bin/pause-linux-amd64 /pause # buildkit",
				Comment:    "buildkit.dockerfile.v0",
				EmptyLayer: false,
			},
			{
				Created:    v1.Time{Time: configCreate},
				CreatedBy:  "USER 65535:65535",
				Comment:    "buildkit.dockerfile.v0",
				EmptyLayer: true,
			},
			{
				Created:    v1.Time{Time: configCreate},
				CreatedBy:  "ENTRYPOINT [\"/pause\"]",
				Comment:    "buildkit.dockerfile.v0",
				EmptyLayer: true,
			},
		},
		OS: "linux",
		RootFS: v1.RootFS{
			Type: "layers",
			DiffIDs: []v1.Hash{
				{
					Algorithm: "sha256",
					Hex:       "dee215ffc666313e1381d3e6e4299a4455503735b8df31c3fa161d2df50860a8",
				},
			},
		},
		Config: v1.Config{
			Entrypoint: []string{"/pause"},
			Env:        []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			User:       "65535:65535",
			WorkingDir: "/",
		},
		OSVersion: "",
		Variant:   "",
	}

	arRef, err := c.inspect(ctx)
	r.NoError(err)
	r.Equal(cfgFile, arRef.ConfigFile)
	r.Equal([]types.BlobInfo{
		{
			SchemaVersion:   2,
			Digest:          "sha256:019d8da33d911d9baabe58ad63dea2107ed15115cca0fc27fc0f627e82a695c1",
			DiffID:          "sha256:dee215ffc666313e1381d3e6e4299a4455503735b8df31c3fa161d2df50860a8",
			CustomResources: nil,
		},
	}, arRef.BlobsInfo)
	r.Equal(&types.ArtifactInfo{
		SchemaVersion: 1,
		Architecture:  "amd64",
		Created:       configCreate,
		OS:            "linux",
	}, arRef.ArtifactInfo)
}
