if config.tilt_subcommand == "down":
    fail("consider using `kubectl delete ns castai-sec")

load('ext://restart_process', 'docker_build_with_restart')
load('ext://namespace', 'namespace_create')

update_settings(max_parallel_updates=16)
allow_k8s_contexts(['tilt', 'kind-tilt', 'docker-desktop', 'minikube'])
namespace = 'castai-sec'
user = os.environ.get('USER', 'unknown-user')

api_url = 'https://api-{}.localenv.cast.ai'.format(user)

namespace_create(namespace)

local_resource(
    'agent-compile',
    'CGO_ENABLED=0 GOOS=linux go build -o bin/castai-sec-agent ./cmd/agent',
    ignore=[
        './bin',
    ],
)

docker_build_with_restart(
    'agent',
    '.',
    entrypoint=['/server'],
    dockerfile='Dockerfile.agent',
    only=[
        './bin/server',
        './db',
    ],
    live_update=[
        sync('./bin/castai-sec-agent', '/usr/local/bin/castai-sec-agent'),
    ],
)

chart_path = '../gh-helm-charts/charts/castai-sec-agent'

agent_dep = helm(
    chart_path,
    name='castai-sec-agent',
    namespace='namespace',
    #values=['{}/tilt.yaml'.format(chart_path)],
    set=[
        'castai.clusterID=todo',
        'castai.apiKey=todo',
        'castai.apiURL='+api_url
    ]
)

k8s_yaml(agent_dep)