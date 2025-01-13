package cgroup

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainerByCgroup(t *testing.T) {
	as := assert.New(t)

	id, typ := GetContainerIdFromCgroup("/kubepods/burstable/pod9729a196c4723b60ab401eaff722982d/d166c6190614efc91956b78e96d74c3fbc96ca8e91948c36de3bc5b0e7b27d48")
	as.Equal(DockerRuntime, typ)
	as.Equal("d166c6190614efc91956b78e96d74c3fbc96ca8e91948c36de3bc5b0e7b27d48", id)

	id, typ = GetContainerIdFromCgroup("/kubepods/besteffort/pod0d08203e-255a-11e9-8cd9-0007cb0b2cc8/671a50f5d60566556912f61511d0ec9e4d5c78d53fbc4676727180438bbbbc55/kube-proxy")
	as.Equal(DockerRuntime, typ)
	as.Equal("671a50f5d60566556912f61511d0ec9e4d5c78d53fbc4676727180438bbbbc55", id)

	id, typ = GetContainerIdFromCgroup("/kubepods/poda38c12e8-255a-11e9-8cd9-0007cb0b2cc8/32c562ed81a2622b37b80cb216859820ba51bd694f60ee4cf10d07a4011266f8")
	as.Equal(DockerRuntime, typ)
	as.Equal("32c562ed81a2622b37b80cb216859820ba51bd694f60ee4cf10d07a4011266f8", id)

	id, typ = GetContainerIdFromCgroup("/docker/63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2d")
	as.Equal(DockerRuntime, typ)
	as.Equal("63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2d", id)

	id, typ = GetContainerIdFromCgroup("/kubepods/poda48c12e8-255a-11e9-8cd9-0007cb0b2cc8/crio-63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2e")
	as.Equal(CrioRuntime, typ)
	as.Equal("63425c4a8b4291744a79dd9011fddc7a1f8ffda61f65d72196aa01d00cae2e2e", id)

	id, typ = GetContainerIdFromCgroup("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2942c55e_c9cb_428a_93f4_eaf89c1f3ce0.slice/crio-49f9e8e5395d57c1083996c09e2e6f042d5fe1ec0310facab32f94912b35ce59.scope")
	as.Equal(CrioRuntime, typ)
	as.Equal("49f9e8e5395d57c1083996c09e2e6f042d5fe1ec0310facab32f94912b35ce59", id)

	id, typ = GetContainerIdFromCgroup("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3e61c214bc3ed9ff81e21474dd6cba17.slice/cri-containerd-c74b0f5062f0bc726cae1e9369ad4a95deed6b298d247f0407475adb23fa3190")
	as.Equal(ContainerdRuntime, typ)
	as.Equal("c74b0f5062f0bc726cae1e9369ad4a95deed6b298d247f0407475adb23fa3190", id)

	id, typ = GetContainerIdFromCgroup("/unified/kubepods/burstable/podaacce108-eb34-4a36-ad41-a9f9d36b3a8f/df4f60dd7f7c9fdc110082804729e637c21c2bca7856b9a6d4bf36cfaef6a2d3")
	as.Equal(DockerRuntime, typ)
	as.Equal("df4f60dd7f7c9fdc110082804729e637c21c2bca7856b9a6d4bf36cfaef6a2d3", id)

	id, typ = GetContainerIdFromCgroup("/system.slice/containerd.service/kubepods-burstable-pod4ed02c0b_0df8_4d14_a30e_fd589ee4143a.slice:cri-containerd:d4a9f9195eaf7e4a729f24151101e1de61f1398677e7b82acfb936dff0b4ce55")
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
