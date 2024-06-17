load('ext://restart_process', 'docker_build_with_restart')
load('ext://helm_remote', 'helm_remote')
load('ext://namespace', 'namespace_create')
load('ext://dotenv', 'dotenv')

if read_file ('.env' , default = '' ):
    dotenv()

update_settings(max_parallel_updates=16)
secret_settings (disable_scrub = True)
allow_k8s_contexts(['kind-kind'])
namespace = 'kvisor'
user = os.environ.get('USER', 'unknown-user')

GOARCH = str(local('go env GOARCH')).rstrip('\n')

namespace_create(namespace)

local_resource(
    'kvisor-agent-compile',
    'CGO_ENABLED=0 GOOS=linux go build -o ./bin/kvisor-agent ./cmd/agent/daemon',
    deps=[
        './cmd/agent',
        './api',
        './pkg/ebpftracer',
        './pkg/cgroup',
        './pkg/containers',
        './pkg/bucketcache',
        './pkg/processtree',
        './pkg/proc',
        './pkg/system',
    ],
)

local_resource(
    'kvisor-controller-compile',
    'CGO_ENABLED=0 GOOS=linux go build -o ./bin/kvisor-controller ./cmd/controller',
    deps=[
        './cmd/controller',
        './api'
    ],
)

local_resource(
    'kvisor-image-scanner-compile',
    'CGO_ENABLED=0 GOOS=linux go build -o ./bin/kvisor-image-scanner ./cmd/imagescan/',
    deps=[
        './cmd/imagescan',
        './api',
    ],
)

local_resource(
    'kvisor-linter-compile',
    'CGO_ENABLED=0 GOOS=linux go build -o ./bin/kvisor-linter ./cmd/linter/',
    deps=[
        './cmd/linter',
        './api',
    ],
)

local_resource(
    'kvisor-event-generator-compile',
    'CGO_ENABLED=0 GOOS=linux go build -o ./bin/kvisor-event-generator ./cmd/event-generator',
    deps=[
        './cmd/event-generator',
    ],
)

local_resource(
    'kvisor-castai-mock-server-compile',
    'CGO_ENABLED=0 GOOS=linux go build -o ./bin/kvisor-mock-server ./cmd/mock-server',
    deps=[
        './cmd/mock-server',
    ],
)

docker_build_with_restart(
    'localhost:5000/kvisor-agent',
    '.',
    entrypoint=['/usr/local/bin/kvisor-agent'],
    dockerfile='Dockerfile.agent.local',
    only=[
        './bin/kvisor-agent',
        './cmd/agent/kubebench/kubebench-rules/',
    ],
    build_args={
        'ARCH': '{}'.format(str(GOARCH))
    },
    live_update=[
        sync('./bin/kvisor-agent', '/usr/local/bin/kvisor-agent'),
        sync('./cmd/agent/kubebench/kubebench-rules', '/etc/kubebench-rules'),
    ],
)

docker_build_with_restart(
    'localhost:5000/kvisor-controller',
    '.',
    entrypoint=['/app/kvisor-controller'],
    dockerfile='Dockerfile.controller.local',
    only=[
        './bin/kvisor-controller',
    ],
    live_update=[
        sync('./bin/kvisor-controller', '/app/kvisor-controller'),
    ],
)

docker_build_with_restart(
    'localhost:5000/kvisor-mock-server',
    '.',
    entrypoint=['/app/kvisor-mock-server'],
    dockerfile='Dockerfile.mock-server',
    only=[
        './bin/kvisor-mock-server',
    ],
    live_update=[
        sync('./bin/kvisor-mock-server', '/app/kvisor-mock-server'),
    ],
)

docker_build(
    'localhost:5000/kvisor-scanners',
    '.',
    dockerfile='Dockerfile.scanners.local',
    match_in_env_vars=True,
)

chart_path = './charts/kvisor'

k8s_yaml(helm(
    chart_path,
    name='castai-kvisor',
    namespace=namespace,
    values=['./charts/kvisor/values-local.yaml']
))

# helm_remote(
#     'grafana',
#     repo_url='https://grafana.github.io/helm-charts',
#     repo_name='grafana',
#     version='6.50.7',
#     namespace=namespace,
#     set=[],
#     values=['./tools/localenv/grafana-values.yaml']
# )

#k8s_resource(workload='kvisor-controller', port_forwards=[6060,5432])

#
# k8s_yaml('./hack/network-test-app.yaml')
