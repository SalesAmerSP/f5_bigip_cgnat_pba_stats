#!/usr/bin/env python3
"""
CGNAT PBA Data Collector - Collects per-subscriber PBA statistics from F5 BIG-IP
and exports to CSV or MySQL.

Replicates the Perl cgnat_db_logging.pl workflow:
  - Fetches all PBA entries and inbound mappings via SSH (lsndb)
  - Aggregates per subscriber IP per pool: total ports used, block count
  - Exports to CSV file or MySQL database

Usage:
    python cgnat_pba_collect.py --output csv
    python cgnat_pba_collect.py --output csv --csv-file /path/to/output.csv
    python cgnat_pba_collect.py --output mysql --db-host localhost --db-name cgnat --db-user root --db-pass changeme
"""

import argparse
import csv
import getpass
import ipaddress
import re
import sys
from collections import defaultdict
from datetime import datetime

import paramiko

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEVICE_NAME = "bigip01"
SSH_CLIENT: paramiko.SSHClient | None = None

OUTPUT_MODE = "csv"  # "csv" or "mysql"

# MySQL defaults (overridden by CLI args)
DB_HOST = "localhost"
DB_PORT = 3306
DB_NAME = "cgnat"
DB_USER = "root"
DB_PASS = ""
DB_TABLE = "pba_stats"

# CSV defaults
CSV_FILE = None  # None = stdout

# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def ssh_connect(host: str, port: int, username: str | None = None,
                password: str | None = None):
    """Establish a persistent SSH connection to the BIG-IP."""
    global SSH_CLIENT
    SSH_CLIENT = paramiko.SSHClient()
    SSH_CLIENT.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    SSH_CLIENT.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=10,
        allow_agent=password is None,
        look_for_keys=password is None,
    )


def ssh_command(cmd: str, timeout: int = 30) -> str:
    """Execute a command on the BIG-IP via the persistent SSH connection."""
    assert SSH_CLIENT is not None, "SSH connection not established"
    _stdin, stdout, stderr = SSH_CLIENT.exec_command(cmd, timeout=timeout)
    output = stdout.read().decode() or stderr.read().decode() or ""
    lines = output.strip().split("\n")
    if len(lines) > 2:
        mid = len(lines) // 2
        if lines[:mid] == lines[mid:]:
            lines = lines[:mid]
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Data collection from BIG-IP
# ---------------------------------------------------------------------------

def get_pool_configs() -> dict:
    """Parse source-translation pool configs from tmsh."""
    raw = ssh_command("tmsh list security nat source-translation one-line")
    pools = {}
    for line in raw.strip().split("\n"):
        if not line.startswith("security nat source-translation"):
            continue
        name_match = re.search(r"source-translation (\S+)", line)
        if not name_match:
            continue
        name = name_match.group(1)
        bs_match = re.search(r"block-size (\d+)", line)
        cbl_match = re.search(r"client-block-limit (\d+)", line)
        addr_match = re.findall(r"addresses \{([^}]+)\}", line)
        block_size = int(bs_match.group(1)) if bs_match else 256
        client_block_limit = int(cbl_match.group(1)) if cbl_match else 1
        addresses = []
        if addr_match:
            addresses = [a.strip().rstrip(" { }") for a in addr_match[0].split("}") if a.strip()]
            addresses = [re.sub(r"\s*\{.*", "", a).strip() for a in addresses if a.strip()]
        pools[name] = {
            "block_size": block_size,
            "client_block_limit": client_block_limit,
            "addresses": addresses,
        }
    return pools


def get_pba_entries() -> list[dict]:
    """Get PBA entries from lsndb."""
    raw = ssh_command("bash -c 'lsndb list pba'")
    entries = []
    for line in raw.strip().split("\n"):
        m = re.match(
            r"(\d+\.\d+\.\d+\.\d+)\s+"
            r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+-\s+(\d+)\s+"
            r"(?:\(\S+\)\s+)?"
            r"(\S+)\s+"
            r"(\d+)",
            line,
        )
        if m:
            entries.append({
                "client_ip": m.group(1),
                "external_ip": m.group(2),
                "port_start": int(m.group(3)),
                "port_end": int(m.group(4)),
                "subscriber_id": m.group(5),
                "ttl": int(m.group(6)),
            })
    return entries


def get_inbound_mappings() -> list[dict]:
    """Get inbound mapping entries to count ports used per block."""
    raw = ssh_command("bash -c 'lsndb list inbound'", timeout=60)
    mappings = []
    for line in raw.strip().split("\n"):
        m = re.match(
            r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+"
            r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+"
            r"\S+\s+"
            r"(?:\s+)?"
            r"(\S+)\s+"
            r"(\d+)",
            line,
        )
        if m:
            mappings.append({
                "translation_ip": m.group(1),
                "translation_port": int(m.group(2)),
                "client_ip": m.group(3),
            })
    return mappings


def find_pool_for_ip(external_ip: str, pools: dict) -> str | None:
    """Find which source-translation pool an external IP belongs to."""
    ext = ipaddress.ip_address(external_ip)
    for pool_name, pool_cfg in pools.items():
        for addr_str in pool_cfg["addresses"]:
            addr_str = addr_str.strip()
            try:
                if "-" in addr_str and "/" not in addr_str:
                    parts = addr_str.split("-")
                    start = ipaddress.ip_address(parts[0].strip())
                    end = ipaddress.ip_address(parts[1].strip())
                    if start <= ext <= end:
                        return pool_name
                elif "/" in addr_str:
                    net = ipaddress.ip_network(addr_str, strict=False)
                    if ext in net:
                        return pool_name
                else:
                    if ext == ipaddress.ip_address(addr_str):
                        return pool_name
            except ValueError:
                continue
    return None

# ---------------------------------------------------------------------------
# Aggregation (mirrors Perl logic)
# ---------------------------------------------------------------------------

def aggregate_per_subscriber(pba_entries: list[dict], mappings: list[dict],
                             pools: dict) -> list[dict]:
    """Aggregate PBA data per subscriber IP per pool.

    For each (client_ip, pool) pair, computes:
      - total ports in use (sum of inbound mappings within allocated blocks)
      - number of port blocks allocated
      - external IPs used (comma-separated)
      - block_size and client_block_limit from pool config
    """
    # Build a fast lookup: (client_ip, translation_ip) -> set of translation ports
    mapping_index: dict[tuple[str, str], set[int]] = defaultdict(set)
    for m in mappings:
        mapping_index[(m["client_ip"], m["translation_ip"])].add(m["translation_port"])

    # Group PBA entries by (client_ip, pool_name)
    client_pool_data: dict[tuple[str, str], dict] = {}

    for entry in pba_entries:
        pool_name = find_pool_for_ip(entry["external_ip"], pools)
        if not pool_name:
            pool_name = "Unknown"
        key = (entry["client_ip"], pool_name)

        if key not in client_pool_data:
            pool_cfg = pools.get(pool_name, {})
            client_pool_data[key] = {
                "client_ip": entry["client_ip"],
                "pool": pool_name,
                "ports": 0,
                "blocks": 0,
                "external_ips": set(),
                "block_size": pool_cfg.get("block_size", 0),
                "client_block_limit": pool_cfg.get("client_block_limit", 0),
            }

        data = client_pool_data[key]
        data["blocks"] += 1
        data["external_ips"].add(entry["external_ip"])

        # Count ports used within this block
        port_set = mapping_index.get((entry["client_ip"], entry["external_ip"]), set())
        ports_used = sum(1 for p in port_set if entry["port_start"] <= p <= entry["port_end"])
        data["ports"] += ports_used

    # Convert sets to strings for output
    results = []
    for data in client_pool_data.values():
        data["external_ips"] = ",".join(sorted(data["external_ips"]))
        results.append(data)

    return sorted(results, key=lambda r: (r["pool"], r["client_ip"]))

# ---------------------------------------------------------------------------
# Output: CSV
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "timestamp", "device", "pool", "client_ip", "ports", "blocks",
    "external_ips", "block_size", "client_block_limit",
]


def export_csv(rows: list[dict], timestamp: str, device: str, csv_file: str | None):
    """Write aggregated data to CSV (file or stdout)."""
    if csv_file:
        fh = open(csv_file, "w", newline="")
        print(f"Writing CSV to {csv_file}", file=sys.stderr)
    else:
        fh = sys.stdout

    writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "timestamp": timestamp,
            "device": device,
            "pool": row["pool"],
            "client_ip": row["client_ip"],
            "ports": row["ports"],
            "blocks": row["blocks"],
            "external_ips": row["external_ips"],
            "block_size": row["block_size"],
            "client_block_limit": row["client_block_limit"],
        })

    if csv_file:
        fh.close()

# ---------------------------------------------------------------------------
# Output: MySQL
# ---------------------------------------------------------------------------

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS {table} (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp       DATETIME NOT NULL,
    device          VARCHAR(64) NOT NULL,
    pool            VARCHAR(128) NOT NULL,
    client_ip       INT UNSIGNED NOT NULL,
    ports           INT NOT NULL,
    blocks          INT NOT NULL,
    external_ips    VARCHAR(512),
    block_size      INT NOT NULL,
    client_block_limit INT NOT NULL,
    INDEX idx_timestamp (timestamp),
    INDEX idx_device_pool (device, pool),
    INDEX idx_client_ip (client_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

INSERT_SQL = """
INSERT INTO {table}
    (timestamp, device, pool, client_ip, ports, blocks, external_ips, block_size, client_block_limit)
VALUES
    (%s, %s, %s, INET_ATON(%s), %s, %s, %s, %s, %s)
"""


def export_mysql(rows: list[dict], timestamp: str, device: str,
                 db_host: str, db_port: int, db_name: str,
                 db_user: str, db_pass: str, db_table: str):
    """Write aggregated data to MySQL."""
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", db_table):
        print(f"ERROR: Invalid table name: {db_table}", file=sys.stderr)
        sys.exit(1)
    try:
        import mysql.connector
    except ImportError:
        print("ERROR: mysql-connector-python not installed. Install with:", file=sys.stderr)
        print("  pip install mysql-connector-python", file=sys.stderr)
        sys.exit(1)

    conn = mysql.connector.connect(
        host=db_host, port=db_port, database=db_name,
        user=db_user, password=db_pass,
    )
    cursor = conn.cursor()

    cursor.execute(CREATE_TABLE_SQL.format(table=db_table))

    insert_sql = INSERT_SQL.format(table=db_table)
    count = 0
    for row in rows:
        cursor.execute(insert_sql, (
            timestamp, device, row["pool"], row["client_ip"],
            row["ports"], row["blocks"], row["external_ips"],
            row["block_size"], row["client_block_limit"],
        ))
        count += 1

    conn.commit()
    cursor.close()
    conn.close()
    print(f"Inserted {count} rows into {db_name}.{db_table}", file=sys.stderr)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Collect CGNAT PBA stats from F5 BIG-IP and export to CSV or MySQL"
    )
    parser.add_argument("--bigip", required=True, metavar="HOST",
                        help="BIG-IP hostname or IP address")
    parser.add_argument("--port", default="22", metavar="PORT",
                        help="SSH port (default: 22)")
    parser.add_argument("--user", metavar="USERNAME",
                        help="SSH username (prompts for password)")
    parser.add_argument("--output", choices=["csv", "mysql"], default=OUTPUT_MODE,
                        help="Output destination (default: csv)")
    parser.add_argument("--device", default=DEVICE_NAME,
                        help=f"Device name for the record (default: {DEVICE_NAME})")

    # CSV options
    parser.add_argument("--csv-file", default=CSV_FILE,
                        help="CSV output file path (default: stdout)")

    # MySQL options
    parser.add_argument("--db-host", default=DB_HOST, help=f"MySQL host (default: {DB_HOST})")
    parser.add_argument("--db-port", type=int, default=DB_PORT, help=f"MySQL port (default: {DB_PORT})")
    parser.add_argument("--db-name", default=DB_NAME, help=f"MySQL database (default: {DB_NAME})")
    parser.add_argument("--db-user", default=DB_USER, help=f"MySQL user (default: {DB_USER})")
    parser.add_argument("--db-pass", default=DB_PASS, help="MySQL password")
    parser.add_argument("--db-table", default=DB_TABLE, help=f"MySQL table (default: {DB_TABLE})")

    args = parser.parse_args()

    username = args.user
    password = None
    if username:
        password = getpass.getpass(f"Password for {username}@{args.bigip}: ")

    try:
        ssh_connect(args.bigip, int(args.port), username=username, password=password)
    except Exception as e:
        print(f"ERROR: Cannot connect to {args.bigip}:{args.port} - {e}", file=sys.stderr)
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("Fetching pool configurations...", file=sys.stderr)
    pools = get_pool_configs()

    print("Fetching PBA entries...", file=sys.stderr)
    pba_entries = get_pba_entries()

    if not pba_entries:
        print("No PBA entries found on the BIG-IP.", file=sys.stderr)
        sys.exit(0)

    print("Fetching inbound mappings...", file=sys.stderr)
    mappings = get_inbound_mappings()

    print("Aggregating per-subscriber data...", file=sys.stderr)
    rows = aggregate_per_subscriber(pba_entries, mappings, pools)
    print(f"Collected {len(rows)} subscriber/pool records.", file=sys.stderr)

    if args.output == "csv":
        export_csv(rows, timestamp, args.device, args.csv_file)
    elif args.output == "mysql":
        export_mysql(rows, timestamp, args.device,
                     args.db_host, args.db_port, args.db_name,
                     args.db_user, args.db_pass, args.db_table)


if __name__ == "__main__":
    main()
