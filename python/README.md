<!-- markdownlint-disable MD033 -->
# CGNAT PBA Monitoring - Python Scripts

## Scripts

### cgnat_pba_stats.py

Interactive query tool that connects to F5 BIG-IP via SSH and displays per-subscriber PBA data.

```bash
python cgnat_pba_stats.py --bigip 10.0.0.1 <host_ip>
python cgnat_pba_stats.py --bigip 10.0.0.1 --pool POOL_NAME
python cgnat_pba_stats.py --bigip 10.0.0.1 --xlated-ip 198.51.100.1
python cgnat_pba_stats.py --bigip 10.0.0.1 --all
python cgnat_pba_stats.py --bigip 10.0.0.1 --summary
python cgnat_pba_stats.py --bigip 10.0.0.1 --user admin --all   # prompts for password when key file is not provided
python cgnat_pba_stats.py --bigip 10.0.0.1 --user admin --key-file ~/.ssh/id_rsa --all   # SSH key authentication
python cgnat_pba_stats.py --bigip 10.0.0.1 --port 47001 --user admin --key-file ~/.ssh/id_rsa --all   # custom SSH port and key auth
python cgnat_pba_stats.py --bigip 10.0.0.1 --all --no-host-key-check  # skip host key verification
```

### cgnat_pba_stats_bigip_compatible.py

Same functionality as `cgnat_pba_stats.py` but designed to run directly on the BIG-IP. Calls `lsndb` and `tmsh` locally without SSH. Compatible with BIG-IP's Python 3.8 and uses only the standard library.

```bash
pba-stats <host_ip>
pba-stats --pool POOL_NAME
pba-stats --xlated-ip 198.51.100.1
pba-stats --all
pba-stats --summary
```

#### Installing on BIG-IP

Use the installer script:

```bash
./install-pba-stats.sh <bigip_host> [--user USERNAME] [--password] [--port PORT] [--insecure]

# Examples
./install-pba-stats.sh 10.0.0.1 --password                              # admin user, prompts for password
./install-pba-stats.sh 10.0.0.1                                         # admin user, SSH key auth
./install-pba-stats.sh 10.0.0.1 --user root --port 47001 --password     # custom user/port + password
./install-pba-stats.sh 10.0.0.1 --insecure                              # skip host key verification
```

The username defaults to `admin`. When `--password` is specified, SSH prompts for the password (once per command). Without `--password`, SSH key-based authentication is used. The installer tries SCP first and falls back to base64 transfer over SSH if SCP is unavailable.

The installer validates the target is a BIG-IP, copies the script to `/shared/scripts/pba-stats`, adds `/shared/scripts` to PATH via `/etc/profile.d/pba-stats.sh`, and configures `/config/startup` to recreate it after upgrades.

<details>
<summary>Manual installation</summary>

```bash
scp cgnat_pba_stats_bigip_compatible.py bigip:/shared/scripts/pba-stats
ssh bigip 'chmod +x /shared/scripts/pba-stats'
ssh bigip 'echo "export PATH=/shared/scripts:\$PATH" > /etc/profile.d/pba-stats.sh'
```

`/etc/profile.d/` does not persist across BIG-IP upgrades. To recreate it on boot, add to `/config/startup`:

```bash
#!/bin/bash
echo 'export PATH=/shared/scripts:$PATH' > /etc/profile.d/pba-stats.sh
```

</details>

### cgnat_api_stats.py

Alternative monitoring script that uses SSH/tmsh instead of lsndb commands. Provides aggregate statistics only — **does not provide per-subscriber details**.

**⚠️ LIMITATION**: This script demonstrates API-based monitoring but currently shows mock data. The iControl REST API provides only aggregate PBA statistics and cannot replace lsndb for detailed subscriber analysis.

```bash
python cgnat_api_stats.py --bigip 10.0.0.1 --pool POOL_NAME
python cgnat_api_stats.py --bigip 10.0.0.1 --user admin --key-file ~/.ssh/id_rsa --pool POOL_NAME
```

## Performance Comparison

Lab test with a pool containing 11 active subscribers (times scale with subscriber count):

| Script                        | Total Time   | Data Detail Level         | Use Case                           |
|-------------------------------|--------------|---------------------------|------------------------------------|
| `cgnat_pba_stats.py` (lsndb)  | ~11 seconds  | Per-subscriber details    | Troubleshooting, detailed analysis |
| `cgnat_api_stats.py` (API)    | ~3 seconds   | Aggregate statistics only | Monitoring, alerting               |

- **lsndb approach**: Provides complete subscriber data (client IPs, port ranges, TTLs, connection details). On large deployments (10k+ subscribers), use `--fast` to reduce collection time significantly.
- **API approach**: 3x faster but lacks per-subscriber detail required for troubleshooting.
- **Recommendation**: Use the API script for high-level monitoring/alerting; use lsndb for detailed subscriber analysis.

**Missing from the API script:**

- Individual client IP mappings
- Port block ranges (start-end)
- Subscriber ID strings
- TTL values for allocations
- Individual connection mappings
- Protocol breakdown per connection
- Connection age information

### cgnat_pba_collect.py

Data collector that aggregates per-subscriber PBA statistics and exports to CSV or MySQL. Designed for periodic collection (e.g., cron).

```bash
# CSV to stdout
python cgnat_pba_collect.py --bigip 10.0.0.1 --output csv

# CSV to file
python cgnat_pba_collect.py --bigip 10.0.0.1 --output csv --csv-file /path/to/output.csv

# MySQL
python cgnat_pba_collect.py --bigip 10.0.0.1 --output mysql \
    --db-host localhost --db-name cgnat \
    --db-user root --db-pass changeme

# Override device name stored in the DB record (default: bigip01)
python cgnat_pba_collect.py --bigip 10.0.0.1 --output mysql --device my-cgnat-01 \
    --db-host localhost --db-name cgnat --db-user root --db-pass changeme

# Override MySQL port or table name
python cgnat_pba_collect.py --bigip 10.0.0.1 --output mysql \
    --db-host localhost --db-port 3307 --db-name cgnat \
    --db-table pba_stats_prod --db-user root --db-pass changeme

# With SSH credentials
python cgnat_pba_collect.py --bigip 10.0.0.1 --user admin --output csv
python cgnat_pba_collect.py --bigip 10.0.0.1 --user admin --key-file ~/.ssh/id_rsa --output csv

# Skip host key verification
python cgnat_pba_collect.py --bigip 10.0.0.1 --output csv --no-host-key-check
```

Per-subscriber aggregated fields: pool, client_ip, ports in use, block count, external IPs, block_size, client_block_limit.

#### MySQL Schema

The script auto-creates the table with the following columns:

| Column             | Type         | Notes                           |
|--------------------|--------------|---------------------------------|
| timestamp          | DATETIME     | Collection time                 |
| device             | VARCHAR(64)  | Device name                     |
| pool               | VARCHAR(128) | Source-translation pool name    |
| client_ip          | INT UNSIGNED | Stored via INET_ATON()          |
| ports              | INT          | Total ports in use              |
| blocks             | INT          | Number of port blocks allocated |
| external_ips       | VARCHAR(512) | Comma-separated translated IPs  |
| block_size         | INT          | Pool's configured block size    |
| client_block_limit | INT          | Pool's max blocks per client    |

## Output Format

Example output:

```text
Mar 04 14:30:00

Pool name: MyPool
Port-overloading-factor:     1     Port block size:  256
Max port blocks per host:   10     Port block active timeout:    0
Used/total port blocks: 5/1008
Host_IP                       External_IP                    Port_Block  Ports_Used/       Block_State/
                                                             Range       Ports_Total       Left_Time(s)
10.0.0.1                      203.0.113.1                    1024-1279        12/256*1    Active/-
10.0.0.2                      203.0.113.1                    1280-1535         0/256*1    Query/120
```

### Block States

- **Active** - Ports currently in use
- **Query** - Block allocated but no active ports, TTL still running
- **Inactive** - Block expired (TTL = 0, no ports in use)
- **Alloc** - Fast-mode only: block allocated with TTL running, active/idle unknown (no inbound data)

## Fast Mode (large deployments)

On deployments with 10,000+ subscribers, `lsndb list inbound` can enumerate millions of active flow entries and take 20–30 minutes to complete. Add `--fast` to skip this call:

```bash
# On-device (bigip_compatible) - skip inbound, show blocks without port counts
pba-stats --all --fast
pba-stats --pool MyPool --fast --json

# --summary --fast is even faster: uses tmctl (instant) + lsndb summary pba
# instead of lsndb list pba entirely
pba-stats --summary --fast
pba-stats --summary --fast --json
```

```bash
# Remote script
python cgnat_pba_stats.py --bigip 10.0.0.1 --all --fast
python cgnat_pba_stats.py --bigip 10.0.0.1 --summary --fast --json
```

### What `--fast` changes

| Feature | Normal | `--fast` |
| --- | --- | --- |
| `lsndb list inbound` called | Yes | No |
| `lsndb list pba` called | Yes | Yes (except `--summary --fast`) |
| `tmctl fw_lsn_pool_pba_stat` called | No | Yes (for `--summary` only) |
| Ports_Used column | Actual count | `-` |
| Block_State | Active / Query / Inactive | Alloc / Inactive (TTL-based) |
| Protocol breakdown | Yes | No (shown as `-`) |
| Per-pool client count | Yes | `-` (total shown at bottom) |

### JSON schema in fast mode

Fast-mode JSON includes `"fast_mode": true` at the root. Fields that require inbound data are set to `null`:

- `ports_used: null` per block
- `utilization_pct: null` per block and per client
- `total_ports_used: null` per pool
- `port_utilization_pct: null` per pool
- `clients: null` per pool (summary fast mode)

Consumers should check `fast_mode` and handle `null` accordingly.

## Enhanced Mode

> Available in `cgnat_pba_stats.py` and `cgnat_pba_stats_bigip_compatible.py` only (not the collector).

Add `--enhanced` to any query mode for additional statistics:

```bash
python cgnat_pba_stats.py --bigip 10.0.0.1 --all --enhanced
pba-stats --pool MyPool --enhanced
pba-stats 10.0.0.1 --enhanced
pba-stats --summary --enhanced
```

### Per-block enhancements (row-level)

- **Utilization %** - Percentage of ports used within each block
- **Protocol breakdown** - TCP vs UDP port counts per block (e.g., `TCP:8 UDP:4`)
- **Subscriber ID** - The subscriber identifier from the PBA entry

### Per-host enhancements (footer after host lookup)

- **Total ports in use** across all blocks with total capacity
- **Overall utilization %** across all allocated blocks
- **Blocks remaining** before hitting the `client_block_limit`
- **Protocol totals** - Aggregate TCP/UDP counts across all blocks
- **External IPs** - All translated IPs assigned to the subscriber

### Per-pool enhancements (footer after pool/all views)

- **Unique clients** count
- **Pool utilization %** - Used blocks vs total available blocks
- **Avg blocks per client**
- **Top 10 subscribers by port usage** - With per-subscriber utilization and external IPs
- **Top 10 subscribers by block count** - Identifies heavy block consumers
- **External IP distribution** - Blocks allocated per external IP with allocation %

### Enhanced summary mode

Adds columns: Total Blocks, Pool%, and Avg Blocks/Client to the summary table.

## JSON Output

> Available in `cgnat_pba_stats.py` and `cgnat_pba_stats_bigip_compatible.py` only (not the collector).

Add `--json` to any query mode to get structured JSON output instead of text:

```bash
python cgnat_pba_stats.py --bigip 10.0.0.1 --all --json
pba-stats 10.0.0.1 --json
pba-stats --summary --json
pba-stats --pool MyPool --json | jq '.clients | sort_by(.ports_used) | reverse | .[0:5]'
```

JSON output is compact (not pretty-printed) for use in API calls and scripting. It always includes the full enhanced data (utilization percentages, protocol breakdowns, per-client aggregates, external IP distribution). The structure varies by mode:

- **Host mode**: `host_ip`, `pool_name`, `blocks_allocated`, `blocks_remaining`, `utilization_pct`, `protocol_totals`, `blocks[]`
- **Pool / xlated-ip / all mode**: Per-pool objects with `blocks[]`, `clients[]`, `external_ip_distribution`
- **Summary mode**: `pools[]` with `clients`, `blocks_used`, `blocks_total`, `pool_utilization_pct`, `avg_blocks_per_client`

## Timing Diagnostics

> Available in `cgnat_pba_stats.py` and `cgnat_pba_stats_bigip_compatible.py`.

Add `--timing` to print per-phase start/stop timestamps and elapsed times to stderr:

```bash
python cgnat_pba_stats.py --bigip 10.0.0.1 --summary --timing
pba-stats --all --fast --timing
```

Sample stderr output:

```text
[14:02:31.443] Starting CGNAT PBA Stats script (lsndb)
[14:02:31.443] Starting: SSH connection establishment
[14:02:31.897] Completed: SSH connection establishment (0.454s)
[14:02:31.897] Starting: Fetching pool configurations
[14:02:32.014] Completed: Fetching pool configurations (0.117s)
[14:02:32.014] Starting: Fetching PBA entries
[14:02:34.291] Completed: Fetching PBA entries (2.277s)

[14:02:34.292] Script completed in 2.849s
```

Timing output goes to stderr so it does not interfere with `--json` consumers or shell pipelines. Without `--timing`, no diagnostic output is produced.

## Requirements

- Python 3.8+ (for the on-device script) / Python 3.9+ (for the remote scripts)
- Dependencies for the remote scripts: `paramiko`, `mysql-connector-python`
  (the on-device script has no third-party dependencies)

### Installing dependencies (hash-verified)

Dependencies are pinned with SHA-256 hashes in [requirements.txt](requirements.txt).
Install with `--require-hashes` to block PyPI mirror tampering and typosquatting:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements.txt
```

If `--require-hashes` fails, the lock file is out of date with respect to your
Python version or a transitive dependency has changed — do not fall back to
an unchecked install. Regenerate with `pip-compile --generate-hashes` from
[requirements.in](requirements.in) instead.
