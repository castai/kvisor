# Third-Party Notices for kvisor-agent

This image contains kvisor source code (Apache License 2.0) and statically
linked third-party Go modules. The table below lists every Go module included
in the binary, with the SPDX license type and a URL pointing to the upstream
LICENSE text. The full license text for any module can be retrieved from the
listed URL or by requesting it from support@cast.ai.

For the kvisor source-level attributions (Trivy, Tracee, runc, falcosecurity
adaptations) see `/licenses/NOTICE.md`.

## Special-case modules

- **github.com/xi2/xz** is released into the public domain by its authors. It
  has no SPDX-classifiable license, but is strictly more permissive than any
  open-source license. The verbatim public-domain notice from upstream is
  available in the module source at
  https://github.com/xi2/xz/blob/master/LICENSE.

## GPL-2.0 eBPF program

The kvisor agent embeds a compiled eBPF program (`tracer_*_bpfel.o`) that is
adapted from the eBPF source in https://github.com/aquasecurity/tracee. eBPF
programs that link Linux kernel headers are conventionally licensed under
GPL-2.0; the adapted source carries `SPDX-License-Identifier: GPL-2.0`.

The corresponding eBPF source is shipped in the kvisor source tree at
`pkg/ebpftracer/c/tracee.bpf.c` and headers under `pkg/ebpftracer/c/headers/`.
A copy of GPL-2.0 is included at `/licenses/GPL-2.0.txt` inside this image.
The full corresponding source is also available on request from
support@cast.ai.

## Go module attributions

| Module | License | Source |
| --- | --- | --- |
| cloud.google.com/go/auth | Apache-2.0 | https://github.com/googleapis/google-cloud-go/blob/auth/v0.17.0/auth/LICENSE |
| cloud.google.com/go/auth/oauth2adapt | Apache-2.0 | https://github.com/googleapis/google-cloud-go/blob/auth/oauth2adapt/v0.2.8/auth/oauth2adapt/LICENSE |
| cloud.google.com/go/compute/apiv1 | Apache-2.0 | https://github.com/googleapis/google-cloud-go/blob/compute/v1.52.0/compute/apiv1/license_codes_client.go |
| cloud.google.com/go/compute/internal | Apache-2.0 | https://github.com/googleapis/google-cloud-go/blob/compute/v1.52.0/compute/LICENSE |
| cloud.google.com/go/compute/metadata | Apache-2.0 | https://github.com/googleapis/google-cloud-go/blob/compute/metadata/v0.9.0/compute/metadata/LICENSE |
| github.com/ClickHouse/ch-go | Apache-2.0 | https://github.com/ClickHouse/ch-go/blob/v0.65.1/LICENSE |
| github.com/ClickHouse/clickhouse-go/v2 | Apache-2.0 | https://github.com/ClickHouse/clickhouse-go/blob/v2.32.2/LICENSE |
| github.com/andybalholm/brotli | MIT | https://github.com/andybalholm/brotli/blob/v1.1.1/LICENSE |
| github.com/asaskevich/govalidator | MIT | https://github.com/asaskevich/govalidator/blob/a9d515a09cc2/LICENSE |
| github.com/aws/aws-sdk-go-v2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/v1.41.1/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/config | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/config/v1.29.13/config/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/credentials | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/credentials/v1.17.66/credentials/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/feature/ec2/imds | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/feature/ec2/imds/v1.16.30/feature/ec2/imds/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/internal/configsources | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/internal/configsources/v1.4.17/internal/configsources/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/internal/endpoints/v2.7.17/internal/endpoints/v2/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/internal/ini | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/internal/ini/v1.8.3/internal/ini/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/internal/sync/singleflight | BSD-3-Clause | https://github.com/aws/aws-sdk-go-v2/blob/v1.41.1/internal/sync/singleflight/LICENSE |
| github.com/aws/aws-sdk-go-v2/service/ec2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/ec2/v1.279.1/service/ec2/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/internal/accept-encoding/v1.13.4/service/internal/accept-encoding/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/internal/presigned-url | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/internal/presigned-url/v1.13.17/service/internal/presigned-url/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/sso | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/sso/v1.25.3/service/sso/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/ssooidc | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/ssooidc/v1.30.1/service/ssooidc/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/sts | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/sts/v1.33.18/service/sts/LICENSE.txt |
| github.com/aws/smithy-go | Apache-2.0 | https://github.com/aws/smithy-go/blob/v1.24.0/LICENSE |
| github.com/aws/smithy-go/internal/sync/singleflight | BSD-3-Clause | https://github.com/aws/smithy-go/blob/v1.24.0/internal/sync/singleflight/LICENSE |
| github.com/beorn7/perks/quantile | MIT | https://github.com/beorn7/perks/blob/v1.0.1/LICENSE |
| github.com/blang/semver/v4 | MIT | https://github.com/blang/semver/blob/v4.0.0/v4/LICENSE |
| github.com/cenkalti/backoff/v4 | MIT | https://github.com/cenkalti/backoff/blob/v4.3.0/LICENSE |
| github.com/cenkalti/backoff/v5 | MIT | https://github.com/cenkalti/backoff/blob/v5.0.2/LICENSE |
| github.com/cespare/xxhash/v2 | MIT | https://github.com/cespare/xxhash/blob/v2.3.0/LICENSE.txt |
| github.com/cilium/cilium | Apache-2.0 | https://github.com/cilium/cilium/blob/v1.17.0-pre.2/LICENSE |
| github.com/cilium/ebpf | MIT | https://github.com/cilium/ebpf/blob/v0.17.3/LICENSE |
| github.com/cilium/hive | Apache-2.0 | https://github.com/cilium/hive/blob/e67f66eb0375/LICENSE |
| github.com/cilium/hive/script | BSD-3-Clause | https://github.com/cilium/hive/blob/e67f66eb0375/script/LICENSE |
| github.com/cilium/proxy/pkg/policy/api/kafka | Apache-2.0 | https://github.com/cilium/proxy/blob/fb67566cbd95/LICENSE |
| github.com/cilium/statedb | Apache-2.0 | https://github.com/cilium/statedb/blob/v0.3.4/LICENSE |
| github.com/cilium/stream | Apache-2.0 | https://github.com/cilium/stream/blob/53c3e5d79744/LICENSE |
| github.com/cilium/workerpool | Apache-2.0 | https://github.com/cilium/workerpool/blob/v1.2.0/LICENSE |
| github.com/containerd/containerd | Apache-2.0 | https://github.com/containerd/containerd/blob/v1.7.29/LICENSE |
| github.com/containerd/containerd/api | Apache-2.0 | https://github.com/containerd/containerd/blob/api/v1.8.0/api/LICENSE |
| github.com/containerd/continuity | Apache-2.0 | https://github.com/containerd/continuity/blob/v0.4.5/LICENSE |
| github.com/containerd/errdefs | Apache-2.0 | https://github.com/containerd/errdefs/blob/v1.0.0/LICENSE |
| github.com/containerd/fifo | Apache-2.0 | https://github.com/containerd/fifo/blob/v1.1.0/LICENSE |
| github.com/containerd/log | Apache-2.0 | https://github.com/containerd/log/blob/v0.1.0/LICENSE |
| github.com/containerd/platforms | Apache-2.0 | https://github.com/containerd/platforms/blob/v1.0.0-rc.1/LICENSE |
| github.com/containerd/ttrpc | Apache-2.0 | https://github.com/containerd/ttrpc/blob/v1.2.7/LICENSE |
| github.com/containerd/typeurl/v2 | Apache-2.0 | https://github.com/containerd/typeurl/blob/v2.2.3/LICENSE |
| github.com/coreos/go-semver/semver | Apache-2.0 | https://github.com/coreos/go-semver/blob/v0.3.1/LICENSE |
| github.com/coreos/go-systemd/v22/journal | Apache-2.0 | https://github.com/coreos/go-systemd/blob/v22.5.0/LICENSE |
| github.com/cyphar/filepath-securejoin/internal/consts | MPL-2.0 | https://github.com/cyphar/filepath-securejoin/blob/v0.6.0/COPYING.md |
| github.com/cyphar/filepath-securejoin/pathrs-lite | MPL-2.0 | https://github.com/cyphar/filepath-securejoin/blob/v0.6.0/pathrs-lite/README.md |
| github.com/davecgh/go-spew/spew | ISC | https://github.com/davecgh/go-spew/blob/d8f796af33cc/LICENSE |
| github.com/distribution/reference | Apache-2.0 | https://github.com/distribution/reference/blob/v0.6.0/LICENSE |
| github.com/docker/go-events | Apache-2.0 | https://github.com/docker/go-events/blob/e31b211e4f1c/LICENSE |
| github.com/elastic/go-freelru | Apache-2.0 | https://github.com/elastic/go-freelru/blob/v0.16.0/LICENSE |
| github.com/emicklei/go-restful/v3 | MIT | https://github.com/emicklei/go-restful/blob/v3.12.1/LICENSE |
| github.com/felixge/httpsnoop | MIT | https://github.com/felixge/httpsnoop/blob/v1.0.4/LICENSE.txt |
| github.com/florianl/go-conntrack | MIT | https://github.com/florianl/go-conntrack/blob/v0.4.0/LICENSE |
| github.com/fsnotify/fsnotify | BSD-3-Clause | https://github.com/fsnotify/fsnotify/blob/v1.9.0/LICENSE |
| github.com/fxamacker/cbor/v2 | MIT | https://github.com/fxamacker/cbor/blob/v2.7.0/LICENSE |
| github.com/gabriel-vasile/mimetype | MIT | https://github.com/gabriel-vasile/mimetype/blob/v1.4.8/LICENSE |
| github.com/go-faster/city | MIT | https://github.com/go-faster/city/blob/v1.0.1/LICENSE |
| github.com/go-faster/errors | BSD-3-Clause | https://github.com/go-faster/errors/blob/v0.7.1/LICENSE |
| github.com/go-logr/logr | Apache-2.0 | https://github.com/go-logr/logr/blob/v1.4.3/LICENSE |
| github.com/go-logr/stdr | Apache-2.0 | https://github.com/go-logr/stdr/blob/v1.2.2/LICENSE |
| github.com/go-openapi/analysis | Apache-2.0 | https://github.com/go-openapi/analysis/blob/v0.23.0/LICENSE |
| github.com/go-openapi/errors | Apache-2.0 | https://github.com/go-openapi/errors/blob/v0.22.0/LICENSE |
| github.com/go-openapi/jsonpointer | Apache-2.0 | https://github.com/go-openapi/jsonpointer/blob/v0.21.0/LICENSE |
| github.com/go-openapi/jsonreference | Apache-2.0 | https://github.com/go-openapi/jsonreference/blob/v0.21.0/LICENSE |
| github.com/go-openapi/loads | Apache-2.0 | https://github.com/go-openapi/loads/blob/v0.22.0/LICENSE |
| github.com/go-openapi/runtime | Apache-2.0 | https://github.com/go-openapi/runtime/blob/v0.28.0/LICENSE |
| github.com/go-openapi/runtime/middleware/denco | MIT | https://github.com/go-openapi/runtime/blob/v0.28.0/middleware/denco/LICENSE |
| github.com/go-openapi/spec | Apache-2.0 | https://github.com/go-openapi/spec/blob/v0.21.0/LICENSE |
| github.com/go-openapi/strfmt | Apache-2.0 | https://github.com/go-openapi/strfmt/blob/v0.23.0/LICENSE |
| github.com/go-openapi/swag | Apache-2.0 | https://github.com/go-openapi/swag/blob/v0.23.0/LICENSE |
| github.com/go-openapi/validate | Apache-2.0 | https://github.com/go-openapi/validate/blob/v0.24.0/LICENSE |
| github.com/go-playground/locales | MIT | https://github.com/go-playground/locales/blob/v0.14.1/LICENSE |
| github.com/go-playground/universal-translator | MIT | https://github.com/go-playground/universal-translator/blob/v0.18.1/LICENSE |
| github.com/go-playground/validator/v10 | MIT | https://github.com/go-playground/validator/blob/v10.26.0/LICENSE |
| github.com/go-viper/mapstructure/v2 | MIT | https://github.com/go-viper/mapstructure/blob/v2.4.0/LICENSE |
| github.com/gogo/protobuf | BSD-3-Clause | https://github.com/gogo/protobuf/blob/v1.3.2/LICENSE |
| github.com/golang/groupcache/lru | Apache-2.0 | https://github.com/golang/groupcache/blob/2c02b8208cf8/LICENSE |
| github.com/golang/protobuf/proto | BSD-3-Clause | https://github.com/golang/protobuf/blob/v1.5.4/LICENSE |
| github.com/google/gnostic-models | Apache-2.0 | https://github.com/google/gnostic-models/blob/v0.6.9/LICENSE |
| github.com/google/go-cmp/cmp | BSD-3-Clause | https://github.com/google/go-cmp/blob/v0.7.0/LICENSE |
| github.com/google/gofuzz | Apache-2.0 | https://github.com/google/gofuzz/blob/v1.2.0/LICENSE |
| github.com/google/gopacket | BSD-3-Clause | https://github.com/google/gopacket/blob/v1.1.19/LICENSE |
| github.com/google/s2a-go | Apache-2.0 | https://github.com/google/s2a-go/blob/v0.1.9/LICENSE.md |
| github.com/google/uuid | BSD-3-Clause | https://github.com/google/uuid/blob/v1.6.0/LICENSE |
| github.com/googleapis/enterprise-certificate-proxy/client | Apache-2.0 | https://github.com/googleapis/enterprise-certificate-proxy/blob/v0.3.7/LICENSE |
| github.com/googleapis/gax-go/v2 | BSD-3-Clause | https://github.com/googleapis/gax-go/blob/v2.15.0/v2/LICENSE |
| github.com/gopacket/gopacket | BSD-3-Clause | https://github.com/gopacket/gopacket/blob/v1.3.1/LICENSE |
| github.com/hamba/avro/v2 | MIT | https://github.com/hamba/avro/blob/v2.27.0/LICENCE |
| github.com/hashicorp/golang-lru/v2 | MPL-2.0 | https://github.com/hashicorp/golang-lru/blob/v2.0.7/LICENSE |
| github.com/hashicorp/golang-lru/v2/simplelru | BSD-3-Clause | https://github.com/hashicorp/golang-lru/blob/v2.0.7/simplelru/LICENSE_list |
| github.com/jedib0t/go-pretty/v6 | MIT | https://github.com/jedib0t/go-pretty/blob/v6.6.7/LICENSE |
| github.com/josharian/intern | MIT | https://github.com/josharian/intern/blob/v1.0.0/license.md |
| github.com/josharian/native | MIT | https://github.com/josharian/native/blob/5c7d0dd6ab86/license |
| github.com/json-iterator/go | MIT | https://github.com/json-iterator/go/blob/v1.1.12/LICENSE |
| github.com/klauspost/compress | Apache-2.0 | https://github.com/klauspost/compress/blob/v1.18.0/LICENSE |
| github.com/klauspost/compress/internal/snapref | BSD-3-Clause | https://github.com/klauspost/compress/blob/v1.18.0/internal/snapref/LICENSE |
| github.com/klauspost/compress/zstd/internal/xxhash | MIT | https://github.com/klauspost/compress/blob/v1.18.0/zstd/internal/xxhash/LICENSE.txt |
| github.com/klauspost/cpuid/v2 | MIT | https://github.com/klauspost/cpuid/blob/v2.2.3/LICENSE |
| github.com/leodido/go-urn | MIT | https://github.com/leodido/go-urn/blob/v1.4.0/LICENSE |
| github.com/liggitt/tabwriter | BSD-3-Clause | https://github.com/liggitt/tabwriter/blob/89fcab3d43de/LICENSE |
| github.com/mackerelio/go-osstat/memory | Apache-2.0 | https://github.com/mackerelio/go-osstat/blob/v0.2.5/LICENSE.txt |
| github.com/mailru/easyjson | MIT | https://github.com/mailru/easyjson/blob/v0.9.0/LICENSE |
| github.com/mattn/go-runewidth | MIT | https://github.com/mattn/go-runewidth/blob/v0.0.16/LICENSE |
| github.com/mdlayher/netlink | MIT | https://github.com/mdlayher/netlink/blob/v1.7.2/LICENSE.md |
| github.com/mdlayher/socket | MIT | https://github.com/mdlayher/socket/blob/v0.5.0/LICENSE.md |
| github.com/miekg/dns | BSD-3-Clause | https://github.com/miekg/dns/blob/v1.1.62/LICENSE |
| github.com/minio/sha256-simd | Apache-2.0 | https://github.com/minio/sha256-simd/blob/v1.0.1/LICENSE |
| github.com/mitchellh/mapstructure | MIT | https://github.com/mitchellh/mapstructure/blob/v1.5.0/LICENSE |
| github.com/moby/locker | Apache-2.0 | https://github.com/moby/locker/blob/v1.0.1/LICENSE |
| github.com/moby/sys/mountinfo | Apache-2.0 | https://github.com/moby/sys/blob/mountinfo/v0.7.2/mountinfo/LICENSE |
| github.com/moby/sys/signal | Apache-2.0 | https://github.com/moby/sys/blob/signal/v0.7.1/signal/LICENSE |
| github.com/moby/sys/user | Apache-2.0 | https://github.com/moby/sys/blob/user/v0.3.0/user/LICENSE |
| github.com/moby/sys/userns | Apache-2.0 | https://github.com/moby/sys/blob/userns/v0.1.0/userns/LICENSE |
| github.com/modern-go/concurrent | Apache-2.0 | https://github.com/modern-go/concurrent/blob/bacd9c7ef1dd/LICENSE |
| github.com/modern-go/reflect2 | Apache-2.0 | https://github.com/modern-go/reflect2/blob/v1.0.2/LICENSE |
| github.com/munnerz/goautoneg | BSD-3-Clause | https://github.com/munnerz/goautoneg/blob/a7dc8b61c822/LICENSE |
| github.com/oklog/ulid | Apache-2.0 | https://github.com/oklog/ulid/blob/v1.3.1/LICENSE |
| github.com/opencontainers/go-digest | Apache-2.0 | https://github.com/opencontainers/go-digest/blob/v1.0.0/LICENSE |
| github.com/opencontainers/image-spec | Apache-2.0 | https://github.com/opencontainers/image-spec/blob/v1.1.1/LICENSE |
| github.com/opencontainers/runtime-spec/specs-go | Apache-2.0 | https://github.com/opencontainers/runtime-spec/blob/v1.2.0/LICENSE |
| github.com/opencontainers/selinux | Apache-2.0 | https://github.com/opencontainers/selinux/blob/v1.13.0/LICENSE |
| github.com/opentracing/opentracing-go | Apache-2.0 | https://github.com/opentracing/opentracing-go/blob/10b1cf09e00b/LICENSE |
| github.com/paulmach/orb | MIT | https://github.com/paulmach/orb/blob/v0.11.1/LICENSE.md |
| github.com/pelletier/go-toml/v2 | MIT | https://github.com/pelletier/go-toml/blob/v2.2.3/LICENSE |
| github.com/petermattis/goid | Apache-2.0 | https://github.com/petermattis/goid/blob/4fcff4a6cae7/LICENSE |
| github.com/pierrec/lz4/v4 | BSD-3-Clause | https://github.com/pierrec/lz4/blob/v4.1.22/LICENSE |
| github.com/pkg/errors | BSD-2-Clause | https://github.com/pkg/errors/blob/v0.9.1/LICENSE |
| github.com/prometheus/client_golang/internal/github.com/golang/gddo/httputil | BSD-3-Clause | https://github.com/prometheus/client_golang/blob/v1.21.1/internal/github.com/golang/gddo/LICENSE |
| github.com/prometheus/client_golang/prometheus | Apache-2.0 | https://github.com/prometheus/client_golang/blob/v1.21.1/LICENSE |
| github.com/prometheus/client_model/go | Apache-2.0 | https://github.com/prometheus/client_model/blob/v0.6.2/LICENSE |
| github.com/prometheus/common | Apache-2.0 | https://github.com/prometheus/common/blob/v0.63.0/LICENSE |
| github.com/prometheus/procfs | Apache-2.0 | https://github.com/prometheus/procfs/blob/v0.15.1/LICENSE |
| github.com/rivo/uniseg | MIT | https://github.com/rivo/uniseg/blob/v0.4.7/LICENSE.txt |
| github.com/sagikazarmark/locafero | MIT | https://github.com/sagikazarmark/locafero/blob/v0.7.0/LICENSE |
| github.com/samber/lo | MIT | https://github.com/samber/lo/blob/v1.49.1/LICENSE |
| github.com/sasha-s/go-deadlock | Apache-2.0 | https://github.com/sasha-s/go-deadlock/blob/v0.3.5/LICENSE |
| github.com/segmentio/asm | MIT | https://github.com/segmentio/asm/blob/v1.2.0/LICENSE |
| github.com/sercand/kuberesolver/v5 | Apache-2.0 | https://github.com/sercand/kuberesolver/blob/v5.1.1/LICENSE |
| github.com/shopspring/decimal | MIT | https://github.com/shopspring/decimal/blob/v1.4.0/LICENSE |
| github.com/sirupsen/logrus | MIT | https://github.com/sirupsen/logrus/blob/v1.9.3/LICENSE |
| github.com/sourcegraph/conc | MIT | https://github.com/sourcegraph/conc/blob/v0.3.0/LICENSE |
| github.com/spf13/afero | Apache-2.0 | https://github.com/spf13/afero/blob/v1.12.0/LICENSE.txt |
| github.com/spf13/cast | MIT | https://github.com/spf13/cast/blob/v1.7.1/LICENSE |
| github.com/spf13/cobra | Apache-2.0 | https://github.com/spf13/cobra/blob/v1.9.1/LICENSE.txt |
| github.com/spf13/pflag | BSD-3-Clause | https://github.com/spf13/pflag/blob/v1.0.6/LICENSE |
| github.com/spf13/viper | MIT | https://github.com/spf13/viper/blob/v1.20.1/LICENSE |
| github.com/subosito/gotenv | MIT | https://github.com/subosito/gotenv/blob/v1.6.0/LICENSE |
| github.com/tklauser/go-sysconf | BSD-3-Clause | https://github.com/tklauser/go-sysconf/blob/v0.3.15/LICENSE |
| github.com/tklauser/numcpus | Apache-2.0 | https://github.com/tklauser/numcpus/blob/v0.10.0/LICENSE |
| github.com/vishvananda/netlink | Apache-2.0 | https://github.com/vishvananda/netlink/blob/976bd8de7d81/LICENSE |
| github.com/vishvananda/netns | Apache-2.0 | https://github.com/vishvananda/netns/blob/v0.0.5/LICENSE |
| github.com/x448/float16 | MIT | https://github.com/x448/float16/blob/v0.8.4/LICENSE |
| go.etcd.io/etcd/api/v3 | Apache-2.0 | https://github.com/etcd-io/etcd/blob/api/v3.5.21/api/LICENSE |
| go.etcd.io/etcd/client/pkg/v3 | Apache-2.0 | https://github.com/etcd-io/etcd/blob/client/pkg/v3.5.21/client/pkg/LICENSE |
| go.etcd.io/etcd/client/v3 | Apache-2.0 | https://github.com/etcd-io/etcd/blob/client/v3.5.21/client/v3/LICENSE |
| go.mongodb.org/mongo-driver | Apache-2.0 | https://github.com/mongodb/mongo-go-driver/blob/v1.17.3/LICENSE |
| go.opentelemetry.io/auto/sdk | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/sdk/v1.2.1/sdk/LICENSE |
| go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go-contrib/blob/instrumentation/net/http/otelhttp/v0.61.0/instrumentation/net/http/otelhttp/LICENSE |
| go.opentelemetry.io/otel | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go/blob/v1.40.0/LICENSE |
| go.opentelemetry.io/otel/metric | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go/blob/metric/v1.40.0/metric/LICENSE |
| go.opentelemetry.io/otel/trace | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go/blob/trace/v1.40.0/trace/LICENSE |
| go.uber.org/dig | MIT | https://github.com/uber-go/dig/blob/v1.17.1/LICENSE |
| go.uber.org/multierr | MIT | https://github.com/uber-go/multierr/blob/v1.11.0/LICENSE.txt |
| go.uber.org/zap | MIT | https://github.com/uber-go/zap/blob/v1.27.0/LICENSE |
| go4.org/netipx | BSD-3-Clause | https://github.com/go4org/netipx/blob/fdeea329fbba/LICENSE |
| golang.org/x/crypto | BSD-3-Clause | https://cs.opensource.google/go/x/crypto/+/v0.46.0:LICENSE |
| golang.org/x/net | BSD-3-Clause | https://cs.opensource.google/go/x/net/+/v0.48.0:LICENSE |
| golang.org/x/oauth2 | BSD-3-Clause | https://cs.opensource.google/go/x/oauth2/+/v0.34.0:LICENSE |
| golang.org/x/sync | BSD-3-Clause | https://cs.opensource.google/go/x/sync/+/v0.19.0:LICENSE |
| golang.org/x/sys | BSD-3-Clause | https://cs.opensource.google/go/x/sys/+/v0.40.0:LICENSE |
| golang.org/x/term | BSD-3-Clause | https://cs.opensource.google/go/x/term/+/v0.38.0:LICENSE |
| golang.org/x/text | BSD-3-Clause | https://cs.opensource.google/go/x/text/+/v0.32.0:LICENSE |
| golang.org/x/time/rate | BSD-3-Clause | https://cs.opensource.google/go/x/time/+/v0.14.0:LICENSE |
| golang.org/x/tools/txtar | BSD-3-Clause | https://cs.opensource.google/go/x/tools/+/v0.39.0:LICENSE |
| google.golang.org/api | BSD-3-Clause | https://github.com/googleapis/google-api-go-client/blob/v0.256.0/LICENSE |
| google.golang.org/api/internal/third_party/uritemplates | BSD-3-Clause | https://github.com/googleapis/google-api-go-client/blob/v0.256.0/internal/third_party/uritemplates/LICENSE |
| google.golang.org/genproto | Apache-2.0 | https://github.com/googleapis/go-genproto/blob/513f23925822/LICENSE |
| google.golang.org/genproto/googleapis/api | Apache-2.0 | https://github.com/googleapis/go-genproto/blob/ff82c1b0f217/googleapis/api/LICENSE |
| google.golang.org/genproto/googleapis/rpc | Apache-2.0 | https://github.com/googleapis/go-genproto/blob/ff82c1b0f217/googleapis/rpc/LICENSE |
| google.golang.org/grpc | Apache-2.0 | https://github.com/grpc/grpc-go/blob/v1.79.3/LICENSE |
| google.golang.org/protobuf | BSD-3-Clause | https://github.com/protocolbuffers/protobuf-go/blob/v1.36.10/LICENSE |
| gopkg.in/evanphx/json-patch.v4 | BSD-3-Clause | https://github.com/evanphx/json-patch/blob/v4.12.0/LICENSE |
| gopkg.in/inf.v0 | BSD-3-Clause | https://github.com/go-inf/inf/blob/v0.9.1/LICENSE |
| gopkg.in/yaml.v3 | MIT | https://github.com/go-yaml/yaml/blob/v3.0.1/LICENSE |
| k8s.io/api | Apache-2.0 | https://github.com/kubernetes/api/blob/v0.32.3/LICENSE |
| k8s.io/apiextensions-apiserver/pkg | Apache-2.0 | https://github.com/kubernetes/apiextensions-apiserver/blob/v0.32.2/LICENSE |
| k8s.io/apimachinery/pkg | Apache-2.0 | https://github.com/kubernetes/apimachinery/blob/v0.32.3/LICENSE |
| k8s.io/apimachinery/third_party/forked/golang | BSD-3-Clause | https://github.com/kubernetes/apimachinery/blob/v0.32.3/third_party/forked/golang/LICENSE |
| k8s.io/client-go | Apache-2.0 | https://github.com/kubernetes/client-go/blob/v0.32.3/LICENSE |
| k8s.io/client-go/third_party/forked/golang/template | BSD-3-Clause | https://github.com/kubernetes/client-go/blob/v0.32.3/third_party/forked/golang/LICENSE |
| k8s.io/cri-api/pkg/apis/runtime/v1 | Apache-2.0 | https://github.com/kubernetes/cri-api/blob/v0.32.2/LICENSE |
| k8s.io/klog/v2 | Apache-2.0 | https://github.com/kubernetes/klog/blob/v2.130.1/LICENSE |
| k8s.io/kube-openapi/pkg | Apache-2.0 | https://github.com/kubernetes/kube-openapi/blob/2c72e554b1e7/LICENSE |
| k8s.io/kube-openapi/pkg/internal/third_party/go-json-experiment/json | BSD-3-Clause | https://github.com/kubernetes/kube-openapi/blob/2c72e554b1e7/pkg/internal/third_party/go-json-experiment/json/LICENSE |
| k8s.io/kube-openapi/pkg/validation/spec | Apache-2.0 | https://github.com/kubernetes/kube-openapi/blob/2c72e554b1e7/pkg/validation/spec/LICENSE |
| k8s.io/utils | Apache-2.0 | https://github.com/kubernetes/utils/blob/24370beab758/LICENSE |
| k8s.io/utils/internal/third_party/forked/golang/net | BSD-3-Clause | https://github.com/kubernetes/utils/blob/24370beab758/internal/third_party/forked/golang/LICENSE |
| sigs.k8s.io/controller-runtime/pkg/client/apiutil | Apache-2.0 | https://github.com/kubernetes-sigs/controller-runtime/blob/v0.19.7/LICENSE |
| sigs.k8s.io/gateway-api/apis/v1 | Apache-2.0 | https://github.com/kubernetes-sigs/gateway-api/blob/v1.2.1/LICENSE |
| sigs.k8s.io/json | Apache-2.0 | https://github.com/kubernetes-sigs/json/blob/cfa47c3a1cc8/LICENSE |
| sigs.k8s.io/mcs-api/pkg | Apache-2.0 | https://github.com/kubernetes-sigs/mcs-api/blob/62ede9a032dc/LICENSE |
| sigs.k8s.io/structured-merge-diff/v4 | Apache-2.0 | https://github.com/kubernetes-sigs/structured-merge-diff/blob/v4.5.0/LICENSE |
| sigs.k8s.io/yaml | Apache-2.0 | https://github.com/kubernetes-sigs/yaml/blob/v1.4.0/LICENSE |
| sigs.k8s.io/yaml/goyaml.v2 | Apache-2.0 | https://github.com/kubernetes-sigs/yaml/blob/v1.4.0/goyaml.v2/LICENSE |
