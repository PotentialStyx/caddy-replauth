#!/bin/bash
set -eou pipefail

xcaddy build --with github.com/PotentialStyx/caddy-replauth=. $@