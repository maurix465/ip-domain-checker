# ip-domain-checker

`ip-domain-checker` is a Python command-line tool that checks one IPv4
address, IPv6 address, or dotted domain against blacklist and threat
intelligence sources defined in an external YAML file.

It currently supports:

- traditional IP DNSBL queries;
- remote TXT and CSV lists over HTTP or HTTPS;
- local TXT and CSV files;
- concurrent checks with isolated per-source failures;
- normalized, exact indicator matching; and
- Rich progress and result output.

The configured sources determine which target types they support. A source
that does not support the current target is reported as `SKIPPED`.

## Requirements

- Python 3.12 or newer
- network access for enabled DNSBL or remote-list sources

## Installation

Install from a repository checkout:

```console
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

On Windows, activate the environment with `.venv\Scripts\activate`.

The installation provides the `check-blacklist` command.

## CLI usage

The target and configuration path are both required:

```console
check-blacklist TARGET --config PATH
```

Examples:

```console
check-blacklist 192.0.2.45 --config blacklists.yaml
check-blacklist 2001:db8::1 --config blacklists.yaml
check-blacklist suspicious.example --config blacklists.yaml
```

Targets are normalized before matching. Domains must be valid dotted domain
names; single-label names such as `localhost` are rejected.

The final table reports each enabled source as one of:

- `LISTED`: the normalized target matched, with evidence;
- `NOT LISTED`: the source completed without a match;
- `SKIPPED`: the source does not support the target type; or
- `ERROR`: the source could not complete, with sanitized structured details.

### Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | The scan completed without source errors and found no listings. |
| `1` | At least one source listed the target and no source failed. |
| `2` | The target, command arguments, or configuration are invalid. |
| `3` | At least one source failed, or the overall scan could not complete. |

Source errors take precedence over listings, so a scan containing both a
`LISTED` result and an `ERROR` result exits with code `3`.

## Configuration

Configuration is YAML with schema version `1`. Unknown fields, duplicate YAML
keys, duplicate source names, unsupported values, and fields that do not apply
to a source kind are rejected. Disabled sources are still validated, then
omitted from the scan. At least one source must be enabled. Configuration files
are loaded safely and limited to 1 MiB.

The repository checkout and source distribution include two configuration
examples. They are not installed as runtime package data by a normal wheel or
`pip` installation; use them from a checkout or an unpacked source
distribution:

- [`examples/blacklists.yaml`](examples/blacklists.yaml) demonstrates the
  configuration schema. Its local source uses a small non-production list,
  while its network sources are disabled placeholders.
- [`examples/public-blacklists.yaml`](examples/public-blacklists.yaml) uses
  real third-party public services for low-volume manual integration testing.
  Those services are independently operated, and their availability, formats,
  policies, and rate limits may change. Review and follow each provider's
  current terms and acceptable-use policy before running it.

### Real-world integration test

From the repository or unpacked source-distribution root, and after reviewing
the third-party provider terms, run a manual test with:

```console
check-blacklist TARGET --config examples/public-blacklists.yaml
```

Do not run this configuration in a tight loop: each invocation queries public
DNSBL services and downloads every applicable remote list. A `LISTED` result
means that the provider currently lists the target according to its own
criteria; it does not by itself prove that the target is malicious.

### Root schema

```yaml
version: 1

defaults:
  dns_timeout_seconds: 5.0
  http_timeout_seconds: 15.0
  max_static_bytes: 10485760

sources:
  - name: local-example
    kind: local_static
    category: example
    supports: [ipv4, ipv6, domain]
    path: lists/local.txt
    format: txt
```

Root fields:

| Field | Required | Description |
| --- | --- | --- |
| `version` | yes | Must be the integer `1`. |
| `defaults` | no | Global timeout and static-list size defaults. |
| `sources` | yes | Non-empty list of source mappings. |

Default fields are optional positive values. Their built-in values are shown
in the example above. `max_static_bytes` is an integer byte limit shared by
local and remote static lists unless a source overrides it.

### Common source fields

Every source supports these fields:

| Field | Required | Description |
| --- | --- | --- |
| `name` | yes | Non-empty name, unique across all sources. |
| `kind` | yes | `dnsbl`, `http_static`, or `local_static`. |
| `category` | yes | Non-empty user-defined category shown in results. |
| `supports` | yes | Non-empty unique list containing `ipv4`, `ipv6`, and/or `domain`. |
| `enabled` | no | Boolean; defaults to `true`. |

### DNSBL source

```yaml
- name: ipv4-dnsbl
  kind: dnsbl
  category: spam
  supports: [ipv4]
  host: dnsbl.example.org
  timeout_seconds: 3.0
```

DNSBL-only fields:

| Field | Required | Description |
| --- | --- | --- |
| `host` | yes | Non-empty DNSBL zone appended to the reversed address. |
| `timeout_seconds` | no | Positive per-source DNS timeout override. |

DNSBL sources may support IPv4 and/or IPv6, but not domains.

### Remote static-list source

```yaml
- name: remote-csv
  kind: http_static
  category: malware
  supports: [ipv4, domain]
  url: https://example.org/indicators.csv
  format: csv
  encoding: utf-8-sig
  comment_prefixes: ["#", ";"]
  timeout_seconds: 10.0
  max_static_bytes: 5242880
  csv:
    has_header: true
    column: indicator
    delimiter: ","
```

Remote-only fields:

| Field | Required | Description |
| --- | --- | --- |
| `url` | yes | Absolute HTTP or HTTPS URL with a host. |
| `timeout_seconds` | no | Positive per-source HTTP timeout override. |

Remote sources also use the static-list fields below.

### Local static-list source

```yaml
- name: local-txt
  kind: local_static
  category: internal
  supports: [ipv4, ipv6, domain]
  path: lists/indicators.txt
  format: txt
```

Local-only field:

| Field | Required | Description |
| --- | --- | --- |
| `path` | yes | File path. Relative paths resolve from the YAML file's directory. |

Local sources also use the static-list fields below.

### Static-list and CSV fields

| Field | Required | Description |
| --- | --- | --- |
| `format` | yes | `txt` or `csv`. |
| `encoding` | no | Python codec name; defaults to `utf-8-sig`. |
| `comment_prefixes` | no | Whole-line comment prefixes; defaults to `#` and `;`. |
| `max_static_bytes` | no | Positive per-source byte-limit override. |
| `csv` | for CSV | CSV parsing mapping; invalid for TXT. |

CSV fields:

| Field | Required | Description |
| --- | --- | --- |
| `has_header` | yes | Whether the first parsed row is a header. |
| `column` | yes | Non-empty header name when `has_header` is true; otherwise a zero-based non-negative integer index. |
| `delimiter` | no | One non-newline character; defaults to `,`. |

## DNSBL behavior

DNSBL checks implement traditional reverse-address queries only:

- IPv4 octets are reversed. For example, `192.0.2.45` with host
  `dnsbl.example.org` queries `45.2.0.192.dnsbl.example.org`.
- IPv6 is expanded to 32 hexadecimal digits and queried in reverse-nibble
  order before the configured host.
- A valid A-record answer means `LISTED`; returned IPv4 addresses are retained
  as evidence.
- `NXDOMAIN` and DNS answers without an A record mean `NOT LISTED`.
- Timeouts, `SERVFAIL`, and other resolver failures produce structured
  `ERROR` results.

The tool does not query domains through DNSBL sources and does not resolve a
domain target to IP addresses automatically.

## Static-list behavior

Remote files are downloaded asynchronously with one shared HTTP session per
scan. Local files are read outside the event loop. Both paths enforce the
configured byte limit before decoding; remote responses are bounded while
streaming even when `Content-Length` is absent or inaccurate.

TXT parsing treats each non-empty, non-comment line as one complete indicator.
CSV parsing extracts one configured column. Indicators are validated and
normalized with the same rules as CLI targets:

- IPv4 and IPv6 addresses are converted to canonical text;
- domains are lowercased and converted to ASCII IDNA form;
- one trailing domain dot is removed;
- malformed indicators are counted and ignored; and
- duplicate normalized indicators are counted and stored once.

Matching is exact. The tool does not perform substring, suffix, wildcard,
CIDR, or IP-range matching. Structurally malformed CSV or undecodable data is
reported as an error. HTTP response bodies are never included in user-facing
errors.

## Docker

From a repository checkout, build the image:

```console
docker build -t ip-domain-checker .
```

Run the bundled local example by mounting the example directory read-only:

```console
docker run --rm \
  --mount type=bind,src="$(pwd)/examples",dst=/data,readonly \
  ip-domain-checker blocked.example --config /data/blacklists.yaml
```

This demonstration target is in the sample list, so the command reports
`LISTED` and exits with code `1`.

For your own configuration, mount the configuration file and any referenced
local lists into the container. Relative local paths are resolved from the
mounted YAML file's directory.

The container runs as a non-root user. Enabled network sources require Docker
DNS and outbound network access.


## License

This project is licensed under the [MIT License](LICENSE).
