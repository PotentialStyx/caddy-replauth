# Repl Auth middleware for [Caddy](https://caddyserver.com)

This module provides a drop in repl auth middleware for [Caddy](https://caddyserver.com). When using [Caddy](https://caddyserver.com) as a reverse proxy with this module, the server being proxied will get the exact same information as if it were hosted on replit[^compat]. An example config can be found in [`config.json5`](config.json5).

To use [Caddy](https://caddyserver.com) with this module you will need to build it using xcaddy.[^xcaddy] You can also use the [`build.sh`](build.sh) script that is provided in this repository.

[^compat]: If something works on replit but not with this caddy module please report an issue as that is a bug.
[^xcaddy]: Read https://caddyserver.com/docs/build#xcaddy for information on how to do that