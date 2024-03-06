#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

dir=$(dirname "$0")
region="us-central1"
project="engineering-test-353509"
user=$USER
cloud_resource_suffix="redis-demo"
for arg in "$@"
do
    case $arg in
        --user=*)
        user="${arg#*=}"
        shift
        ;;
    esac
done

echo "User: ${user}"
echo "Region: ${region}"
echo "Project: ${project}"

get_external_ip() {
  local name="${1}"
  echo $(gcloud compute addresses describe $name --region=$region --project=$project --format=json | jq -r '.address')
}

create_external_ip() {
  local name="${1}"
  gcloud compute addresses create $name --region=$region --project=$project
}

check_instance() {
  local name="${1}"
  gcloud compute instances describe $name --zone="${region}-a" --project=$project >>/dev/null 2>&1
}

create_firewall_rules() {
  local name="${1}"
  gcloud compute firewall-rules create $name \
    --project=$project \
    --allow=tcp:80,tcp:443,tcp:6379 \
    --description="Allow incoming traffic for http and redis" \
    --direction=INGRESS \
    --target-tags="$name"
}

create_instance() {
  local name="${1}"
  local address="${2}"

  gcloud compute instances create $name \
      --address=$address \
      --zone="${region}-a" \
      --project=$project \
      --boot-disk-size=100 \
      --image=ubuntu-2004-focal-v20220303a \
      --image-project=ubuntu-os-cloud \
      --machine-type=e2-small \
      --can-ip-forward \
      --tags="$name" \
      --metadata-from-file=startup-script=${dir}/init_script.sh \
      --metadata=user=${user}
}

cloud_resource_name="${user}-${cloud_resource_suffix}"
external_ip=$(get_external_ip $cloud_resource_name)
if [ "${external_ip}" == "" ]; then
  echo "Creating external IP '${cloud_resource_name}'"
  create_external_ip $cloud_resource_name
  external_ip=$(get_external_ip $cloud_resource_name)
fi
echo "ExternalIP: ${external_ip}"

if ! check_instance "$cloud_resource_name"; then
  echo "Creating instance '${cloud_resource_name}'"
  create_instance "$cloud_resource_name" "$external_ip"

  echo "Creating firewall rules '${cloud_resource_name}'"
  create_firewall_rules "$cloud_resource_name"
fi
