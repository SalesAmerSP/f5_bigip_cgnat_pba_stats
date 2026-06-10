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

from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import os
import re
import sys
from datetime import datetime

import paramiko

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEVICE_NAME = "bigip01"
SSH_CLIENT: paramiko.SSHClient | None = None
SSH_CONNECT_PARAMS: dict | None = None

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
                password: str | None = None, key_filename: str | None = None,
                no_host_key_check: bool = False):
    """Establish a persistent SSH connection to the BIG-IP."""
    global SSH_CONNECT_PARAMS
    SSH_CONNECT_PARAMS = {
        "hostname": host, "port": port, "username": username,
        "password": password, "key_filename": key_filename, "timeout": 10,
        "allow_agent": password is None,
        "look_for_keys": password is None and key_filename is None,
        "no_host_key_check": no_host_key_check,
    }
    _do_ssh_connect()


def _do_ssh_connect():
    """Internal: create and connect SSH client using stored params."""
    global SSH_CLIENT
    params = SSH_CONNECT_PARAMS
    assert params is not None, "ssh_connect() must be called before _do_ssh_connect()"
    SSH_CLIENT = paramiko.SSHClient()
    if params["no_host_key_check"]:
        SSH_CLIENT.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        SSH_CLIENT.load_system_host_keys()
        SSH_CLIENT.set_missing_host_key_policy(paramiko.WarningPolicy())
    SSH_CLIENT.connect(
        hostname=params["hostname"], port=params["port"],
        username=params["username"], password=params["password"],
        key_filename=params["key_filename"], timeout=params["timeout"],
        allow_agent=params["allow_agent"],
        look_for_keys=params["look_for_keys"],
    )


def ssh_command(cmd: str, timeout: int = 30) -> str:
    """Execute a command on the BIG-IP via SSH, reconnecting if needed.

    BIG-IP only supports one channel per SSH connection, so each command
    after the first requires a fresh connection. A brief delay avoids
    connection rate-limiting on the BIG-IP side.
    """
    _, stdout, stderr = _exec_with_retry(cmd, timeout)
    output = stdout.read().decode() or stderr.read().decode() or ""
    lines = output.strip().split("\n")
    if len(lines) > 2:
        mid = len(lines) // 2
        if lines[:mid] == lines[mid:]:
            lines = lines[:mid]
    return "\n".join(lines)


def _exec_with_retry(cmd: str, timeout: int):
    """Run exec_command, reconnecting up to 3 times on SSHException."""
    import time
    global SSH_CLIENT
    assert SSH_CLIENT is not None, "SSH connection not established"
    try:
        return SSH_CLIENT.exec_command(cmd, timeout=timeout)
    except paramiko.SSHException:
        try:
            SSH_CLIENT.close()
        except Exception:
            pass
        last_err: Exception = paramiko.SSHException("unreachable")
        for attempt in range(3):
            try:
                time.sleep(1 + attempt)
                _do_ssh_connect()
                assert SSH_CLIENT is not None
                return SSH_CLIENT.exec_command(cmd, timeout=timeout)
            except Exception as e:
                last_err = e
        raise last_err


def ssh_stream_command(cmd: str, timeout: int = 3600):
    """Execute a command via SSH and yield stdout lines one at a time.

    lsndb dumps grow to several GB on busy CGNAT deployments; reading the
    whole channel into one string (ssh_command) plus per-flow parsing is
    what ran collection hosts out of memory, so large dumps must be consumed
    line-by-line and never buffered whole.
    """
    _, stdout, _ = _exec_with_retry(cmd, timeout)
    for line in stdout:
        yield line

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
        # Capture the full inner body of `addresses { ... }` including the
        # nested `{ }` that follows each entry. `[^}]+` stopped at the first
        # inner brace and only captured the first address.
        addr_match = re.findall(r"addresses \{((?:[^{}]*\{[^{}]*\})*[^{}]*)\}", line)
        if not bs_match or not cbl_match:
            print(f"WARNING: Could not parse block-size/client-block-limit for {name}", file=sys.stderr)
            continue
        block_size = int(bs_match.group(1))
        client_block_limit = int(cbl_match.group(1))
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
    """Get PBA entries from lsndb (streamed; deduplicates repeated block lines)."""
    pattern = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)\s+"
        r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+-\s+(\d+)\s+"
        r"(?:\(\S+\)\s+)?"
        r"(\S+)\s+"
        r"(\d+)"
    )
    entries = []
    seen = set()
    for line in ssh_stream_command("bash -c 'lsndb list pba'"):
        m = pattern.match(line)
        if not m:
            continue
        # Block ranges are unique per external IP; a repeat means the BIG-IP
        # echoed the output twice (the quirk ssh_command's halves-dedup handles).
        key = (m.group(1), m.group(2), m.group(3))
        if key in seen:
            continue
        seen.add(key)
        entries.append({
            "client_ip": m.group(1),
            "external_ip": m.group(2),
            "port_start": int(m.group(3)),
            "port_end": int(m.group(4)),
            "subscriber_id": m.group(5),
            "ttl": int(m.group(6)),
        })
    return entries


def get_inbound_index(pba_entries: list[dict]) -> dict:
    """
    Stream 'lsndb list inbound' and aggregate flows per allocated block:
        (client_ip, external_ip, port_start, port_end) -> <bitmap of used ports>

    The inbound dump has one line per active flow (millions on a busy box).
    Folding flows into per-block bitmaps as they stream by keeps memory
    bounded by allocated blocks instead of active flows.
    """
    blocks_by_key: dict[tuple[str, str], list] = {}
    index: dict = {}
    for e in pba_entries:
        key = (e["client_ip"], e["external_ip"], e["port_start"], e["port_end"])
        index[key] = 0
        blocks_by_key.setdefault((e["client_ip"], e["external_ip"]), []).append(
            (e["port_start"], e["port_end"], key)
        )
    pattern = re.compile(
        r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+"
        r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+"
        r"\S+\s+"
        r"(?:\s+)?"
        r"(\S+)\s+"
        r"(\d+)"
    )
    for line in ssh_stream_command("bash -c 'lsndb list inbound'"):
        m = pattern.match(line)
        if not m:
            continue
        blocks = blocks_by_key.get((m.group(3), m.group(1)))
        if not blocks:
            continue
        port = int(m.group(2))
        for start, end, key in blocks:
            if start <= port <= end:
                index[key] |= 1 << (port - start)
                break
    return index


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
                    if int(start) <= int(ext) <= int(end):
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

def aggregate_per_subscriber(pba_entries: list[dict], mapping_index: dict,
                             pools: dict) -> list[dict]:
    """Aggregate PBA data per subscriber IP per pool.

    For each (client_ip, pool) pair, computes:
      - total ports in use (sum of inbound mappings within allocated blocks)
      - number of port blocks allocated
      - external IPs used (comma-separated)
      - block_size and client_block_limit from pool config
    """
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
        bitmap = mapping_index.get(
            (entry["client_ip"], entry["external_ip"], entry["port_start"], entry["port_end"]), 0
        )
        data["ports"] += bin(bitmap).count("1")

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
    fh = None
    try:
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
    finally:
        if fh and fh is not sys.stdout:
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
    cursor = None
    try:
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
        print(f"Inserted {count} rows into {db_name}.{db_table}", file=sys.stderr)
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()

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
                        help="SSH username; prompts for password unless --key-file is set")
    parser.add_argument("--key-file", metavar="FILE",
                        help="SSH private key file for publickey authentication")
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
    parser.add_argument("--no-host-key-check", action="store_true",
                        help="Disable SSH host key verification (insecure)")

    args = parser.parse_args()

    username = args.user
    password = None
    key_file = os.path.expanduser(args.key_file) if args.key_file else None
    if username and not key_file:
        password = getpass.getpass(f"Password for {username}@{args.bigip}: ")
    if key_file and not os.path.isfile(key_file):
        print(f"ERROR: SSH key file not found: {key_file}", file=sys.stderr)
        sys.exit(1)

    try:
        ssh_connect(args.bigip, int(args.port), username=username,
                    password=password, key_filename=key_file,
                    no_host_key_check=args.no_host_key_check)
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
    mapping_index = get_inbound_index(pba_entries)

    print("Aggregating per-subscriber data...", file=sys.stderr)
    rows = aggregate_per_subscriber(pba_entries, mapping_index, pools)
    print(f"Collected {len(rows)} subscriber/pool records.", file=sys.stderr)

    if args.output == "csv":
        export_csv(rows, timestamp, args.device, args.csv_file)
    elif args.output == "mysql":
        export_mysql(rows, timestamp, args.device,
                     args.db_host, args.db_port, args.db_name,
                     args.db_user, args.db_pass, args.db_table)


if __name__ == "__main__":
    main()
