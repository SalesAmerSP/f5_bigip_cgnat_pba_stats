# CGNAT PBA Monitoring - Python Scripts

## Scripts

### cgnat_pba_stats.py

Interactive query tool that connects to F5 BIG-IP via SSH and displays per-subscriber PBA data.

```
python cgnat_pba_stats.py --bigip 10.0.0.1 <host_ip>
python cgnat_pba_stats.py --bigip 10.0.0.1 --pool POOL_NAME
python cgnat_pba_stats.py --bigip 10.0.0.1 --xlated-ip 198.51.100.1
python cgnat_pba_stats.py --bigip 10.0.0.1 --all
python cgnat_pba_stats.py --bigip 10.0.0.1 --summary
python cgnat_pba_stats.py --bigip 10.0.0.1 --user admin --all   # prompts for password
python cgnat_pba_stats.py --bigip 10.0.0.1 --port 47001 --all   # custom SSH port
```

### cgnat_pba_stats_bigip_compatible.py

Same functionality as `cgnat_pba_stats.py` but designed to run directly on the BIG-IP. Calls `lsndb` and `tmsh` locally without SSH. Compatible with BIG-IP's Python 3.8.

```
pba-stats <host_ip>
pba-stats --pool POOL_NAME
pba-stats --all
pba-stats --summary
```

#### Installing on BIG-IP

Use the installer script:

```bash
./install-pba-stats.sh <bigip_host> [username] [ssh_port]

# Examples
./install-pba-stats.sh 10.0.0.1
./install-pba-stats.sh bigip.example.com admin             # prompts for password
./install-pba-stats.sh bigip.example.com admin 47001       # custom port + password
```

When a username is specified, the script prompts for the password. Without a username, SSH will use key-based authentication.

The installer validates the target is a BIG-IP, copies the script to `/shared/scripts/pba-stats`, creates a symlink at `/usr/local/bin/pba-stats`, and adds symlink recreation to `/config/startup` for boot persistence.

<details>
<summary>Manual installation</summary>

```bash
scp cgnat_pba_stats_bigip_compatible.py bigip:/shared/scripts/pba-stats
ssh bigip 'chmod +x /shared/scripts/pba-stats'
ssh bigip 'ln -sf /shared/scripts/pba-stats /usr/local/bin/pba-stats'
```

The symlink in `/usr/local/bin/` does not persist across BIG-IP upgrades. To recreate it on boot, add to `/config/startup`:

```bash
#!/bin/bash
ln -sf /shared/scripts/pba-stats /usr/local/bin/pba-stats
```

</details>

### cgnat_pba_collect.py

Data collector that aggregates per-subscriber PBA statistics and exports to CSV or MySQL. Designed for periodic collection (e.g., cron).

```
# CSV to stdout
python cgnat_pba_collect.py --bigip 10.0.0.1 --output csv

# CSV to file
python cgnat_pba_collect.py --bigip 10.0.0.1 --output csv --csv-file /path/to/output.csv

# MySQL
python cgnat_pba_collect.py --bigip 10.0.0.1 --output mysql \
    --db-host localhost --db-name cgnat \
    --db-user root --db-pass secret

# With SSH credentials
python cgnat_pba_collect.py --bigip 10.0.0.1 --user admin --output csv
```

Per-subscriber aggregated fields: pool, client_ip, ports in use, block count, external IPs, block_size, client_block_limit.

#### MySQL Schema

The script auto-creates the table with the following columns:

| Column | Type | Notes |
|--------|------|-------|
| timestamp | DATETIME | Collection time |
| device | VARCHAR(64) | Device name |
| pool | VARCHAR(128) | Source-translation pool name |
| client_ip | INT UNSIGNED | Stored via INET_ATON() |
| ports | INT | Total ports in use |
| blocks | INT | Number of port blocks allocated |
| external_ips | VARCHAR(512) | Comma-separated translated IPs |
| block_size | INT | Pool's configured block size |
| client_block_limit | INT | Pool's max blocks per client |

## Output Format

Example output:

```
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

## Enhanced Mode

Add `--enhanced` to any query mode for additional statistics:

```
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

Add `--json` to any query mode to get structured JSON output instead of text:

```
python cgnat_pba_stats.py --bigip 10.0.0.1 --all --json
pba-stats 10.0.0.1 --json
pba-stats --summary --json
pba-stats --pool MyPool --json | jq '.clients | sort_by(.ports_used) | reverse | .[0:5]'
```

JSON output is compact (not pretty-printed) for use in API calls and scripting. It always includes the full enhanced data (utilization percentages, protocol breakdowns, per-client aggregates, external IP distribution). The structure varies by mode:

- **Host mode**: `host_ip`, `pool_name`, `blocks_allocated`, `blocks_remaining`, `utilization_pct`, `protocol_totals`, `blocks[]`
- **Pool / xlated-ip / all mode**: Per-pool objects with `blocks[]`, `clients[]`, `external_ip_distribution`
- **Summary mode**: `pools[]` with `clients`, `blocks_used`, `blocks_total`, `pool_utilization_pct`, `avg_blocks_per_client`

## Requirements

- Python 3.8+ (for local script on BIG-IP) / Python 3.10+ (for remote scripts)
- `paramiko` (for remote SSH scripts)
- `mysql-connector-python` (only if using MySQL export in collector)
