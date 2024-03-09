#! /bin/bash

apt install -y debian-keyring debian-archive-keyring apt-transport-https lsb-release curl gpg

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list

curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list

apt update
apt install -y caddy redis

mkdir -p /etc/caddy
user=$(curl http://metadata/computeMetadata/v1/instance/attributes/user -H "Metadata-Flavor: Google")
cat <<EOT > /etc/caddy/Caddyfile
redis-storage.tools {
 respond "Hello, world!"
}
EOT
systemctl restart caddy
