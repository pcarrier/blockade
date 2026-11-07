# Blockade

Blockade is a streaming HTTP/1 reverse proxy for one plain HTTP origin. It uses a local ASN database and keeps rolling request and byte quotas by ASN and reduced User-Agent. Run it behind a TLS terminator for HTTPS ingress.

Static binaries for x86-64 and ARM64 Linux are available from [GitHub Releases](https://github.com/pcarrier/blockade/releases). Download the binary for your architecture and make it executable with `chmod +x`. Each release includes `SHA256SUMS` for verification. GitHub Actions also keeps the binaries as workflow artifacts and publishes them when a `v*` tag is pushed.

```sh
direnv allow
nix build
export PATH="$PWD/result/bin:$PATH"

blockade proxy --asn-db /path/to/GeoLite2-ASN.mmdb --upstream http://127.0.0.1:8000
```

Run management commands in another terminal with the binary on `PATH`.

```sh
blockade stats
blockade list
blockade reject 'Foo/bar 1.2.3 extra'
blockade allow 'Foo/bar'
blockade clear 'Foo/bar'
blockade unblock AS12345 'Foo/bar'
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
| `--max-requests N` | Admitted requests per key per window | `1000` |
| `--max-bytes N` | Combined upload and download body bytes per key per window | `67108864` |
| `--trusted-proxy IP` | Ingress that overwrites `X-Forwarded-For` with one client IP | Unset |
| `--garbage-file FILE` | Serve a local file with `200 OK` to denylisted UAs | Unset |
| `--instance NAME` | Control socket suffix for multiple proxies under one user | `default` |
| `--state-dir DIR` | Directory for quota checkpoints and UA rules | `./blockade-state` or `./blockade-<instance>-state` |
| `--checkpoint-secs N` | Seconds between quota checkpoints | `5` |
| `--empty-allowlist` | Initialize a new rules file with no built-in entries | Off |

## State on disk

Blockade keeps counters in memory and atomically checkpoints changed buckets to `quotas.tsv` in the state directory. It writes a final checkpoint on `SIGTERM` or `Ctrl+C`. A crash can lose traffic counted since the last successful checkpoint. On restart, Blockade reloads buckets that are still in the window. The default window covers the current UTC day and the previous 29 UTC days. Changing the bucket length starts fresh counters.

`blocks.tsv` records automatic blocks as they happen. Blocks survive restart, counter expiry, and allowlist changes until `unblock` removes them. `rules.tsv` stores the allowlist and denylist. Each successful rule change replaces that file before the command returns. `.lock` prevents two proxies from writing to the same state directory.

## Forwarding and limits

The TCP peer supplies the client IP unless it matches `--trusted-proxy`. A trusted ingress must provide exactly one IP in `X-Forwarded-For`. When the ASN database has no match, Blockade uses the client IP as the network key. The reduced UA is the lowercase first token with a numeric slash version removed and a 64-byte cap. `Foo/bar 1.2.3 extra` becomes `foo/bar`, `curl/8.5` becomes `curl`, and missing UAs use `-`.

Quota blocks return `429` and denylisted UAs return `403`. The first request beyond the request limit is rejected. The body frame that crosses the byte limit is counted and can pass. Later frames for a blocked key stop, which can truncate an in-flight transfer. Byte totals count body data handed to the HTTP writer in both directions, excluding headers and framing. Rejected requests do not extend the window.

With `--garbage-file FILE`, Blockade loads a regular file of up to 16 MiB at startup and serves it as `application/octet-stream` to denylisted UAs. These requests bypass the origin. Restart the proxy to load a changed file. Automatic quota blocks still return `429`.

The origin receives the configured upstream `Host` and a fresh `X-Forwarded-For`. HTTP upgrades and CONNECT return `501`. Chunked bodies stream through the proxy with trailers discarded. Blockade caps concurrent client connections at 1,024 and quota keys at 16,384, including blocked keys. A new key receives `503` while the table is full.
