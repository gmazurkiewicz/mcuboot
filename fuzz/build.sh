#!/bin/bash

set -e

export HOST_UID=$(id -u)
export HOST_GID=$(id -g)

docker compose build

# Defaults to docker-compose.yml's command (./run.sh); pass e.g. ./coverage.sh
# to run something else in the same container.
#
# Rootless docker maps container UID 0 to the host user, so running as the
# host UID/GID (mapped to an unrelated subordinate UID) can't write to the
# bind-mounted repo; run as root instead in that case.
if docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q rootless; then
    docker compose run --rm --user root fuzz "$@"
else
    docker compose run --rm fuzz "$@"
fi
