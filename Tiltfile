if config.tilt_subcommand == "down":
    fail("consider using `kubectl delete ns castai-sec")

load('ext://restart_process', 'docker_build_with_restart')
load('ext://namespace', 'namespace_create')

update_settings(max_parallel_updates=16)
secret_settings ( disable_scrub = True)
allow_k8s_contexts(['tilt', 'kind-tilt', 'docker-desktop', 'minikube'])
namespace = 'castai-sec'
user = os.environ.get('USER', 'unknown-user')
api_url = os.environ.get('API_URL', 'https://api-{}.localenv.cast.ai'.format(user))
api_key = os.environ.get('API_KEY', 'not-set')
cluster_id = os.environ.get('CLUSTER_ID', 'not-set')

namespace_create(namespace)

local_resource(
    'agent-compile',
    'CGO_ENABLED=0 GOOS=linux go build -o ./bin/castai-sec-agent ./cmd/agent',
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

docker_build_with_restart(
    'agent',
    '.',
    entrypoint=['/usr/local/bin/castai-sec-agent'],
    dockerfile='Dockerfile.agent',
    only=[
        './bin/castai-sec-agent',
    ],
    live_update=[
        sync('./bin/castai-sec-agent', '/usr/local/bin/castai-sec-agent'),
    ],
)

docker_build_with_restart(
    'imgcollector',
    '.',
    entrypoint=['/usr/local/bin/castai-imgcollector'],
    dockerfile='Dockerfile.imgcollector',
    only=[
        './bin/castai-imgcollector',
    ],
    live_update=[
        sync('./bin/castai-imgcollector', '/usr/local/bin/castai-imgcollector'),
    ],
)

chart_path = '../gh-helm-charts/charts/castai-sec-agent'

k8s_yaml(helm(
    chart_path,
    name='castai-sec-agent',
    namespace=namespace,
    set=[
        'castai.clusterID='+cluster_id,
        'castai.apiKey='+api_key,
        'castai.apiURL='+api_url,
        'image.repository=agent',
        'features.imagescan.image.repository=imgcollector',
        'agentContainerSecurityContext=null'
    ]
))

if api_url == 'http://mockapi':
    local_resource(
        'mockapi-compile',
        'CGO_ENABLED=0 GOOS=linux go build -o ./bin/mockapi ./tools/mockapi',
        deps=[
            './toos/mockapi',
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
