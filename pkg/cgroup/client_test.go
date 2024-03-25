package cgroup

import (
	"path"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFromProcessCgroupFile(t *testing.T) {
	t.Skip() // TODO: Fix tests after NewFromProcessCgroupFile is used.

	cg, err := NewFromProcessCgroupFile(path.Join("fixtures/proc/100/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, "/system.slice/docker.service", cg.Id)
	assert.Equal(t, V1, cg.Version)
	assert.Equal(t, "/system.slice/docker.service", cg.ContainerID)
	assert.Equal(t, DockerRuntime, cg.ContainerRuntime)

	assert.Equal(t,
		map[string]string{
			"blkio":        "/system.slice/docker.service",
			"cpu":          "/system.slice/docker.service",
			"cpuacct":      "/system.slice/docker.service",
			"cpuset":       "/",
			"devices":      "/system.slice/docker.service",
			"freezer":      "/",
			"hugetlb":      "/",
			"memory":       "/system.slice/docker.service",
			"name=systemd": "/system.slice/docker.service",
			"net_cls":      "/",
			"net_prio":     "/",
			"perf_event":   "/",
			"pids":         "/system.slice/docker.service",
		},
		cg.subsystems,
	)

	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/200/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, V1, cg.Version)
	assert.Equal(t, "/docker/b43d92bf1e5c6f78bb9b7bc6f40721280299855ba692092716e3a1b6c0b86f3f", cg.Id)
	assert.Equal(t, "b43d92bf1e5c6f78bb9b7bc6f40721280299855ba692092716e3a1b6c0b86f3f", cg.ContainerID)
	assert.Equal(t, DockerRuntime, cg.ContainerRuntime)

	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/300/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, V1, cg.Version)
	assert.Equal(t, "/kubepods/burstable/pod6a4ce4a0-ba47-11ea-b2a7-0cc47ac5979e/17db96a24ae1e9dd57143e62b1cb0d2d35e693c65c774c7470e87b0572e07c1a", cg.Id)
	assert.Equal(t, "17db96a24ae1e9dd57143e62b1cb0d2d35e693c65c774c7470e87b0572e07c1a", cg.ContainerID)
	assert.Equal(t, DockerRuntime, cg.ContainerRuntime)

	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/400/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, V2, cg.Version)
	assert.Equal(t, "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8712f785_1a3e_41ec_a00b_e2dcc77431cb.slice/docker-73051af271105c07e1f493b34856a77e665e3b0b4fc72f76c807dfbffeb881bd.scope", cg.Id)
	assert.Equal(t, "73051af271105c07e1f493b34856a77e665e3b0b4fc72f76c807dfbffeb881bd", cg.ContainerID)
	assert.Equal(t, DockerRuntime, cg.ContainerRuntime)

	baseCgroupPath = "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podc83d0428_58af_41eb_8dba_b9e6eddffe7b.slice/docker-0e612005fd07e7f47e2cd07df99a2b4e909446814d71d0b5e4efc7159dd51252.scope"
	defer func() {
		baseCgroupPath = ""
	}()
	cg, err = NewFromProcessCgroupFile(path.Join("fixtures/proc/500/cgroup"))
	assert.Nil(t, err)
	assert.Equal(t, V2, cg.Version)
	assert.Equal(t, "/system.slice/docker-ba7b10d15d16e10e3de7a2dcd408a3d971169ae303f46cfad4c5453c6326fee2.scope", cg.Id)
	assert.Equal(t, "ba7b10d15d16e10e3de7a2dcd408a3d971169ae303f46cfad4c5453c6326fee2", cg.ContainerID)
	assert.Equal(t, DockerRuntime, cg.ContainerRuntime)
}

func TestContainerByCgroup(t *testing.T) {
	as := assert.New(t)

	id, typ := getContainerIdFromCgroup("/kubepods/burstable/pod9729a196c4723b60ab401eaff722982d/d166c6190614efc91956b78e96d74c3fbc96ca8e91948c36de3bc5b0e7b27d48")
	as.Equal(DockerRuntime, typ)
	as.Equal("d166c6190614efc91956b78e96d74c3fbc96ca8e91948c36de3bc5b0e7b27d48", id)

	id, typ = getContainerIdFromCgroup("/kubepods/besteffort/pod0d08203e-255a-11e9-8cd9-0007cb0b2cc8/671a50f5d60566556912f61511d0ec9e4d5c78d53fbc4676727180438bbbbc55/kube-proxy")
	as.Equal(DockerRuntime, typ)
	as.Equal("671a50f5d60566556912f61511d0ec9e4d5c78d53fbc4676727180438bbbbc55", id)

	id, typ = getContainerIdFromCgroup("/kubepods/poda38c12e8-255a-11e9-8cd9-0007cb0b2cc8/32c562ed81a2622b37b80cb216859820ba51bd694f60ee4cf10d07a4011266f8")
	as.Equal(DockerRuntime, typ)
	as.Equal("32c562ed81a2622b37b80cb216859820ba51bd694f60ee4cf10d07a4011266f8", id)

	id, typ = getContainerIdFromCgroup("/docker/63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2d")
	as.Equal(DockerRuntime, typ)
	as.Equal("63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2d", id)

	id, typ = getContainerIdFromCgroup("/kubepods/poda48c12e8-255a-11e9-8cd9-0007cb0b2cc8/crio-63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2e")
	as.Equal(CrioRuntime, typ)
	as.Equal("63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2e", id)

	id, typ = getContainerIdFromCgroup("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2942c55e_c9cb_428a_93f4_eaf89c1f3ce0.slice/crio-49f9e8e5395d57c1083996c09e2e6f042d5fe1ec0310facab32f94912b35ce59.scope")
	as.Equal(CrioRuntime, typ)
	as.Equal("49f9e8e5395d57c1083996c09e2e6f042d5fe1ec0310facab32f94912b35ce59", id)

	id, typ = getContainerIdFromCgroup("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3e61c214bc3ed9ff81e21474dd6cba17.slice/cri-containerd-c74b0f5062f0bc726cae1e9369ad4a95deed6b298d247f0407475adb23fa3190")
	as.Equal(ContainerdRuntime, typ)
	as.Equal("c74b0f5062f0bc726cae1e9369ad4a95deed6b298d247f0407475adb23fa3190", id)

	id, typ = getContainerIdFromCgroup("/unified/kubepods/burstable/podaacce108-eb34-4a36-ad41-a9f9d36b3a8f/df4f60dd7f7c9fdc110082804729e637c21c2bca7856b9a6d4bf36cfaef6a2d3")
	as.Equal(DockerRuntime, typ)
	as.Equal("df4f60dd7f7c9fdc110082804729e637c21c2bca7856b9a6d4bf36cfaef6a2d3", id)

	id, typ = getContainerIdFromCgroup("/system.slice/containerd.service/kubepods-burstable-pod4ed02c0b_0df8_4d14_a30e_fd589ee4143a.slice:cri-containerd:d4a9f9195eaf7e4a729f24151101e1de61f1398677e7b82acfb936dff0b4ce55")
	as.Equal(ContainerdRuntime, typ)
	as.Equal("d4a9f9195eaf7e4a729f24151101e1de61f1398677e7b82acfb936dff0b4ce55", id)
}

func newTestClient() *Client {
	return &Client{
		version: V2,
		cgRoot:  "fixtures",
	}
}

func getFileInode(entryPath string) (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(entryPath, &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}
