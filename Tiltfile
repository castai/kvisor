if config.tilt_subcommand == "down":
    fail("consider using `kubectl delete ns castai-sec")

load('ext://restart_process', 'docker_build_with_restart')
load('ext://namespace', 'namespace_create')
load('ext://dotenv', 'dotenv')

if read_file ('.env' , default = '' ):
    dotenv()

update_settings(max_parallel_updates=16)
secret_settings ( disable_scrub = True)
allow_k8s_contexts(['tilt', 'kind-tilt', 'docker-desktop', 'minikube'])
namespace = 'kvisor'
user = os.environ.get('USER', 'unknown-user')
api_url = os.environ.get('API_URL', 'http://mockapi')
api_key = os.environ.get('API_KEY', 'not-set')
cluster_id = os.environ.get('CLUSTER_ID', 'not-set')
image_scan_enabled = os.environ.get('IMAGE_SCAN_ENABLED', 'false')

namespace_create(namespace)

local_resource(
    'agent-compile',
    'CGO_ENABLED=0 GOOS=linux go build -o ./bin/castai-kvisor ./cmd/agent',
    deps=[
        './'
    ],
    ignore=[
        './bin',
    ],
)

local_resource(
    'imgcollector-compile',
    'CGO_ENABLED=0 GOOS=linux go build -o ./bin/castai-imgcollector ./cmd/imgcollector',
    deps=[
        './cmd/imgcollector'
    ],
    ignore=[
        './bin',
    ],
)

local_resource(
    'imgcollector-docker-build',
    'docker build -t localhost:5000/kvisor-imgcollector . -f Dockerfile.imgcollector && docker push localhost:5000/kvisor-imgcollector',
    deps=[
        './bin/castai-imgcollector'
    ],
)

docker_build_with_restart(
    'agent',
    '.',
    entrypoint=['/usr/local/bin/castai-kvisor'],
    dockerfile='Dockerfile.tilt',
    only=[
        './bin/castai-kvisor',
    ],
    live_update=[
        sync('./bin/castai-kvisor', '/usr/local/bin/castai-kvisor'),
    ],
)

chart_path = './charts/castai-kvisor'
k8s_yaml(helm(
    chart_path,
    name='castai-kvisor',
    namespace=namespace,
    set=[
        'castai.clusterID='+cluster_id,
        'castai.apiKey='+api_key,
        'castai.apiURL='+api_url,
        'image.repository=agent',
        'structuredConfig.linter.enabled=true',
        'structuredConfig.kubeBench.enabled=true',
        'structuredConfig.kubeBench.scanInterval=2s',
        'structuredConfig.imageScan.enabled='+image_scan_enabled,
        'structuredConfig.imageScan.scanInterval=2s',
        'structuredConfig.imageScan.image.name=localhost:5000/kvisor-imgcollector:latest',
        'structuredConfig.imageScan.image.pullPolicy=Always',
        'agentContainerSecurityContext=null'
    ]
))

if api_url == 'http://mockapi':
    local_resource(
        'mockapi-compile',
        'CGO_ENABLED=0 GOOS=linux go build -o ./bin/mockapi ./tools/mockapi',
        deps=[
            './tools/mockapi',
        ],
    )
    docker_build_with_restart(
        'mockapi',
        '.',
        entrypoint=['/usr/local/bin/mockapi'],
        dockerfile='Dockerfile.mockapi',
        only=[
            './bin/mockapi',
        ],
        live_update=[
            sync('./bin/mockapi', '/usr/local/bin/mockapi'),
        ],
    )
    k8s_yaml('./tools/mockapi/k8s.yaml')
