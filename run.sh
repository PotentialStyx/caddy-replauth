#!/bin/bash
set -eou pipefail

. build.sh --with github.com/caddyserver/json5-adapter 
./caddy run --adapter json5 --config config.json5