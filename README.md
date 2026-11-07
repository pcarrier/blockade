# Blockade

Blockade is a streaming HTTP/1 reverse proxy for one plain HTTP origin. It uses a local ASN database and keeps rolling request and byte quotas by ASN and reduced User-Agent.

## Install on Linux

The examples run Nginx or Caddy, Blockade, and the origin on one host. The public frontend terminates HTTPS and proxies to Blockade at `127.0.0.1:8080`. Blockade sends requests to the origin at `127.0.0.1:8000` over HTTP. Keep both internal listeners on loopback and replace `example.com` with your domain.

### Install the binary and ASN database

Download the latest static binary for x86-64 or ARM64, verify its checksum, and install it as `blockade`. [GitHub Releases](https://github.com/pcarrier/blockade/releases)

```sh
(
    set -eu
    arch=$(uname -m)
    case "$arch" in
        x86_64|aarch64) ;;
        *) echo "Unsupported architecture $arch" >&2; exit 1 ;;
    esac
    asset="blockade-$arch-linux"
    base=https://github.com/pcarrier/blockade/releases/latest/download
    work=$(mktemp -d)
    trap 'rm -f -- "$work/$asset" "$work/SHA256SUMS"; rmdir -- "$work"' EXIT
    cd "$work"
    curl -fsSLO "$base/$asset"
    curl -fsSLO "$base/SHA256SUMS"
    sha256sum --check --ignore-missing SHA256SUMS
    sudo install -Dm755 "$asset" /usr/local/bin/blockade
)
```

Obtain an ASN MMDB database such as MaxMind GeoLite2 ASN. Extract `GeoLite2-ASN.mmdb` and install it where the service can read it. [MaxMind database downloads and updates](https://dev.maxmind.com/geoip/updating-databases/)

```sh
sudo install -Dm644 GeoLite2-ASN.mmdb /etc/blockade/GeoLite2-ASN.mmdb
```

### Run Blockade as a service

Create a dedicated service account once.

```sh
sudo useradd --system --user-group --no-create-home \
    --home-dir /var/lib/blockade --shell /usr/sbin/nologin blockade
```

Save this unit as `/etc/systemd/system/blockade.service`. Set `--upstream` to the address of your origin. `StateDirectory` creates `/var/lib/blockade` for the service account. [systemd service directory settings](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#StateDirectory=)

```ini
[Unit]
Description=Blockade reverse proxy
After=network.target

[Service]
User=blockade
Group=blockade
StateDirectory=blockade
StateDirectoryMode=0700
ExecStart=/usr/local/bin/blockade proxy \
    --listen 127.0.0.1:8080 \
    --upstream http://127.0.0.1:8000 \
    --asn-db /etc/blockade/GeoLite2-ASN.mmdb \
    --trusted-proxy 127.0.0.1 \
    --state-dir /var/lib/blockade
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now blockade
```

Choose one of the frontends below. Because Blockade trusts the loopback frontend, configure it to overwrite `X-Forwarded-For` with exactly one address. The examples use the IP of the client connected directly to the frontend. If your origin generates absolute URLs, configure its public URL as `https://example.com`.

### Nginx

For an existing HTTPS virtual host, keep its certificate settings and replace the application's proxy location with the `location /` block below. For a new virtual host, add the `server` block in a file included by Nginx's `http` context, such as `/etc/nginx/conf.d/blockade.conf`. Use the paths to your TLS certificate chain and private key. The two buffering settings keep uploads and downloads streaming through Blockade. [Nginx proxy directives](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name example.com;

    ssl_certificate /etc/ssl/example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_request_buffering off;
        proxy_buffering off;
    }
}
```

If Nginx itself serves your site's files, move its file-serving configuration into a separate loopback virtual host. A simple static origin looks like this.

```nginx
server {
    listen 127.0.0.1:8000;
    root /srv/www/example.com;
}
```

```sh
sudo nginx -t && sudo systemctl reload nginx
```

### Caddy

Add this site to `/etc/caddy/Caddyfile`, or replace the application's existing proxy configuration. Clear the incoming `X-Forwarded-For` chain so Caddy builds it from the direct client address. Point the domain's DNS at the server and make ports 80 and 443 reachable for Caddy's automatic HTTPS. [Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) · [Automatic HTTPS](https://caddyserver.com/docs/automatic-https)

```caddyfile
example.com {
	request_header -X-Forwarded-For
	reverse_proxy 127.0.0.1:8080
}
```

If Caddy itself serves your site's files, put `file_server` in a separate loopback site.

```caddyfile
http://127.0.0.1:8000 {
	root * /srv/www/example.com
	file_server
}
```

```sh
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && sudo systemctl reload caddy
```

### Verify and manage

Send a request from another machine, then check `stats` on the server. The `blockade-install-check` row should show the client's ASN or fallback IP.

```sh
curl -fsS -A 'blockade-install-check/1.0' https://example.com/
```

Run management commands as the service user.

```sh
sudo -u blockade /usr/local/bin/blockade stats
sudo -u blockade /usr/local/bin/blockade list
sudo -u blockade /usr/local/bin/blockade reject 'Foo/bar 1.2.3 extra'
sudo -u blockade /usr/local/bin/blockade allow 'Foo/bar'
sudo -u blockade /usr/local/bin/blockade clear 'Foo/bar'
sudo -u blockade /usr/local/bin/blockade unblock AS12345 'Foo/bar'
```

`stats` prints rolling totals by network and UA. `list` shows automatic blocks and the UA allowlist and denylist. `allow` exempts a UA from new quota blocks, `reject` denies it, and `clear` removes its allowlist or denylist rule. A UA can be on one list at a time. Rules apply across all networks. Allowlisted traffic still contributes to the counters. `unblock` removes an automatic block and resets quota counters for that ASN or fallback IP and UA. It works even after all of the blocked key's counters have aged out. Management commands run as the same Linux user and with the same `--instance` as the proxy.

New state directories start with `curl`, `wget`, `httpie`, `python-requests`, `go-http-client`, `mozilla`, and `okhttp` allowlisted. `Mozilla/5.0` reduces to `mozilla`. Pass `--empty-allowlist` to initialize without built-in rules. To add Mozilla to an existing state directory, run `blockade allow Mozilla`. Clients can spoof the UA used to match a rule.

## CLI options

| Proxy option | Meaning | Default |
| --- | --- | --- |
| `--upstream URL` | Origin as `http://host[:port]` | Required |
| `--asn-db FILE` | Path to an ASN MMDB file | Required |
| `--listen ADDR` | Listen IP and port | `127.0.0.1:8080` |
| `--interval-secs N` | Seconds in one bucket | `86400` |
| `--window-intervals N` | Buckets in the rolling window, including the current one. Range 1–60. | `30` |
| `--max-requests N` | Admitted requests per key per window | `1000000` |
| `--max-bytes N` | Combined upload and download body bytes per key per window | `10000000000` (10 GB) |
| `--trusted-proxy IP` | Ingress that overwrites `X-Forwarded-For` with one client IP | Unset |
| `--garbage-file FILE` | Serve a local file with `200 OK` for quota blocks and denylisted UAs | Unset |
| `--instance NAME` | Control socket suffix for multiple proxies under one user | `default` |
| `--state-dir DIR` | Directory for quota checkpoints and UA rules | `./blockade-state` or `./blockade-<instance>-state` |
| `--checkpoint-secs N` | Seconds between quota checkpoints | `5` |
| `--empty-allowlist` | Initialize a new rules file with no built-in entries | Off |

## State on disk

Blockade keeps counters in memory and atomically checkpoints changed buckets to `quotas.tsv` in the state directory. It writes a final checkpoint on `SIGTERM` or `Ctrl+C`. A crash can lose traffic counted since the last successful checkpoint. On restart, Blockade reloads buckets that are still in the window. The default window covers the current UTC day and the previous 29 UTC days. Changing the bucket length starts fresh counters.

`blocks.tsv` records automatic blocks as they happen. Blocks survive restart, counter expiry, and allowlist changes until `unblock` removes them. `rules.tsv` stores the allowlist and denylist. Each successful rule change replaces that file before the command returns. `.lock` prevents two proxies from writing to the same state directory.

## Forwarding and limits

The TCP peer supplies the client IP unless it matches `--trusted-proxy`. A trusted ingress must provide exactly one IP in `X-Forwarded-For`. When the ASN database has no match, Blockade uses the client IP as the network key. The reduced UA is the lowercase first token with a numeric slash version removed and a 64-byte cap. `Foo/bar 1.2.3 extra` becomes `foo/bar`, `curl/8.5` becomes `curl`, and missing UAs use `-`.

By default, quota blocks return `429` and denylisted UAs return `403`. The first request beyond the request limit is rejected. The body frame that crosses the byte limit is counted and can pass. Later frames for a blocked key stop, which can truncate an in-flight transfer. Byte totals count body data handed to the HTTP writer in both directions, excluding headers and framing. Rejected requests do not extend the window.

With `--garbage-file FILE`, Blockade loads a regular file of up to 16 MiB at startup and serves it with `200 OK` and `application/octet-stream` for quota blocks and denylisted UAs. Requests blocked at admission receive the file directly from Blockade. Restart the proxy to load a changed file.

The origin receives the configured upstream `Host` and a fresh `X-Forwarded-For`. HTTP upgrades and CONNECT return `501`. Chunked bodies stream through the proxy with trailers discarded.

## License

Blockade is licensed under the [MIT License](LICENSE).
