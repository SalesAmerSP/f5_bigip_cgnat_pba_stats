#!/usr/bin/env python3
"""
CGNAT PBA Stats - Query per-subscriber port block allocations on F5 BIG-IP via SSH
using lsndb and tmsh commands.

Usage:
    python cgnat_pba_stats.py --bigip bigip.example.com <host_ip>
    python cgnat_pba_stats.py --bigip bigip.example.com --pool [pool_name]
    python cgnat_pba_stats.py --bigip bigip.example.com --all
    python cgnat_pba_stats.py --bigip bigip.example.com --summary
"""

import argparse
import getpass
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime

import paramiko


class Timer:
    """Simple timing context manager."""
    def __init__(self, description: str):
        self.description = description
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Starting: {self.description}", file=sys.stderr)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        end_time = time.time()
        duration = end_time - self.start_time
        print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Completed: {self.description} ({duration:.3f}s)", file=sys.stderr)


SSH_CLIENT: paramiko.SSHClient | None = None
SSH_CONNECT_PARAMS: dict | None = None


def ssh_connect(host: str, port: int, username: str | None = None,
                password: str | None = None, key_filename: str | None = None,
                no_host_key_check: bool = False):
    """Establish a persistent SSH connection to the BIG-IP."""
    global SSH_CLIENT, SSH_CONNECT_PARAMS
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
    after the first requires a fresh connection. A brief delay and retry
    avoids connection rate-limiting on the BIG-IP side.
    """
    import time
    global SSH_CLIENT
    assert SSH_CLIENT is not None, "SSH connection not established"
    try:
        _, stdout, stderr = SSH_CLIENT.exec_command(cmd, timeout=timeout)
    except paramiko.SSHException:
        try:
            SSH_CLIENT.close()
        except Exception:
            pass
        last_err = None
        for attempt in range(3):
            try:
                time.sleep(1 + attempt)
                _do_ssh_connect()
                _, stdout, stderr = SSH_CLIENT.exec_command(cmd, timeout=timeout)
                last_err = None
                break
            except Exception as e:
                last_err = e
        if last_err is not None:
            raise last_err
    output = stdout.read().decode() or stderr.read().decode() or ""
    lines = output.strip().split("\n")
    if len(lines) > 2:
        mid = len(lines) // 2
        if lines[:mid] == lines[mid:]:
            lines = lines[:mid]
    return "\n".join(lines)


def get_tmctl_pool_stats() -> dict:
    """
    Return per-pool block counts from tmctl (instant, no lsndb needed).
    Uses fw_lsn_pool_pba_stat which reads directly from TMM shared memory.
    Returns dict: pool_name -> {active_port_blocks, total_port_blocks}
    Returns empty dict if tmctl is unavailable (older TMOS).
    """
    raw = ssh_command(
        "bash -c 'tmctl -c -s name,active_port_blocks,total_port_blocks fw_lsn_pool_pba_stat 2>/dev/null'"
    )
    stats: dict = {}
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("name"):
            continue
        parts = line.split(",")
        if len(parts) != 3:
            continue
        name = parts[0].rsplit("/", 1)[-1]  # strip partition prefix
        try:
            stats[name] = {
                "active_port_blocks": int(parts[1]),
                "total_port_blocks": int(parts[2]),
            }
        except ValueError:
            continue
    return stats


def get_pba_client_summary() -> dict:
    """
    Return per-client block count from 'lsndb summary pba'.
    Produces one output line per subscriber (vs one per block for lsndb list pba),
    so it is faster on large deployments when per-pool IP breakdown is not needed.
    Returns dict: client_ip -> block_count
    """
    raw = ssh_command("bash -c 'lsndb summary pba'")
    clients: dict = {}
    for line in raw.strip().split("\n"):
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s*$", line)
        if m:
            clients[m.group(1)] = int(m.group(2))
    return clients


def get_pool_configs() -> dict:
    """Parse source-translation pool configs from tmsh to get block-size and client-block-limit."""
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
    """Get PBA entries from lsndb."""
    raw = ssh_command("bash -c 'lsndb list pba'")
    entries = []
    for line in raw.strip().split("\n"):
        # Match lines like: 10.1.10.59   10.1.100.11:1280  - 1535   No-lookup   3600
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
        # Match: 10.1.100.15:1104   10.1.10.53:37968   No-lookup   TCP   0
        m = re.match(
            r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+"
            r"(\d+\.\d+\.\d+\.\d+):(\d+)\s+"
            r"\S+\s+"  # subscriber ID
            r"(?:\s+)?"  # optional DS-Lite tunnel
            r"(\S+)\s+"  # protocol
            r"(\d+)",   # age
            line,
        )
        if m:
            mappings.append({
                "translation_ip": m.group(1),
                "translation_port": int(m.group(2)),
                "client_ip": m.group(3),
                "client_port": int(m.group(4)),
                "protocol": m.group(5),
                "age": int(m.group(6)),
            })
    return mappings


def build_mapping_indexes(mappings: list[dict]) -> tuple[dict[tuple[str, str], list[dict]], dict[str, list[dict]]]:
    """Build lookup indexes for inbound mappings."""
    mapping_index: dict[tuple[str, str], list[dict]] = {}
    client_mapping_index: dict[str, list[dict]] = defaultdict(list)
    for m in mappings:
        key = (m["client_ip"], m["translation_ip"])
        mapping_index.setdefault(key, []).append(m)
        client_mapping_index[m["client_ip"]].append(m)
    return mapping_index, client_mapping_index


def get_persistence_entries() -> dict:
    """Get persistence entries mapping client IPs to external IPs."""
    raw = ssh_command("bash -c 'lsndb list persistence'")
    persist = {}
    for line in raw.strip().split("\n"):
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)", line)
        if m:
            persist[m.group(1)] = {
                "translation_ip": m.group(2),
                "ttl": int(m.group(3)),
            }
    return persist


def find_pool_for_ip(external_ip: str, pools: dict) -> tuple[str, dict]:
    """Find which source-translation pool an external IP belongs to.
    Returns (pool_name, pool_config) or (None, None).
    """
    import ipaddress

    ext = ipaddress.ip_address(external_ip)
    for pool_name, pool_cfg in pools.items():
        for addr_str in pool_cfg["addresses"]:
            addr_str = addr_str.strip()
            try:
                if "-" in addr_str and "/" not in addr_str:
                    # Range like 10.1.100.11-10.1.100.15
                    parts = addr_str.split("-")
                    start = ipaddress.ip_address(parts[0].strip())
                    end = ipaddress.ip_address(parts[1].strip())
                    if start <= ext <= end:
                        return pool_name, pool_cfg
                elif "/" in addr_str:
                    net = ipaddress.ip_network(addr_str, strict=False)
                    if ext in net:
                        return pool_name, pool_cfg
                else:
                    if ext == ipaddress.ip_address(addr_str):
                        return pool_name, pool_cfg
            except ValueError:
                continue
    return None, None


def infer_block_size(entries: list[dict]) -> int:
    """Infer block size from PBA entries' port ranges when pool config is unavailable."""
    if entries:
        e = entries[0]
        return e["port_end"] - e["port_start"] + 1
    return 0


def unknown_pool_cfg(entries: list[dict]) -> dict:
    """Build a placeholder pool config for entries that don't match any known pool."""
    return {"block_size": infer_block_size(entries), "client_block_limit": 0, "addresses": []}


def count_ports_used(client_ip: str, translation_ip: str, port_start: int,
                     port_end: int, mapping_index) -> int | None:
    """
    Count unique ports used within a port block for a client.
    Returns None when mapping_index is None (fast mode — inbound data not collected).
    """
    if mapping_index is None:
        return None
    ports = set()
    for m in mapping_index.get((client_ip, translation_ip), []):
        if port_start <= m["translation_port"] <= port_end:
            ports.add(m["translation_port"])
    return len(ports)


def count_ports_by_protocol(client_ip: str, translation_ip: str, port_start: int,
                            port_end: int, mapping_index) -> dict[str, int]:
    """Count ports used per protocol within a port block for a client."""
    if mapping_index is None:
        return {}
    proto_counts: dict[str, int] = defaultdict(int)
    for m in mapping_index.get((client_ip, translation_ip), []):
        if port_start <= m["translation_port"] <= port_end:
            proto_counts[m.get("protocol", "?")] += 1
    return dict(proto_counts)


def determine_block_state(ports_used: int | None, ttl: int, block_idle_timeout: int = 0) -> str:
    """
    Determine block state.
    ports_used=None means fast mode (no inbound data); TTL is used as the only signal.
    """
    if ports_used is None:
        return "Alloc" if ttl > 0 else "Inactive"
    if ports_used > 0:
        return "Active"
    if ttl > 0:
        return "Query"
    return "Inactive"


def filter_entries_by_pool(pba_entries: list[dict], pool_name: str, pools: dict) -> list[dict]:
    """Filter PBA entries to only those whose external IP belongs to the named pool."""
    pool_cfg = pools.get(pool_name)
    if not pool_cfg:
        return []
    filtered = []
    for entry in pba_entries:
        found_pool, _ = find_pool_for_ip(entry["external_ip"], pools)
        if found_pool == pool_name:
            filtered.append(entry)
    return filtered


def calc_total_port_blocks(pool_cfg: dict) -> int:
    """Calculate total possible port blocks for a pool based on address space and block size."""
    import ipaddress
    total_ips = 0
    for addr_str in pool_cfg["addresses"]:
        addr_str = addr_str.strip()
        try:
            if "-" in addr_str and "/" not in addr_str:
                parts = addr_str.split("-")
                start = int(ipaddress.ip_address(parts[0].strip()))
                end = int(ipaddress.ip_address(parts[1].strip()))
                total_ips += end - start + 1
            elif "/" in addr_str:
                total_ips += ipaddress.ip_network(addr_str, strict=False).num_addresses
            else:
                total_ips += 1
        except ValueError:
            continue
    port_range = 65535 - 1024 + 1  # 64512 usable ports
    blocks_per_ip = port_range // pool_cfg["block_size"]
    return total_ips * blocks_per_ip


def print_pool_header(pool_name: str, pool_cfg: dict, used_blocks: int, total_blocks: int,
                      per_host: bool = False, enhanced: bool = False):
    """Print the pool header.
    per_host=True shows 'Used/total port blocks per host' (host-ip mode).
    per_host=False shows 'Used/total port blocks' (pool/all mode).
    """
    block_size = pool_cfg["block_size"]
    max_blocks = pool_cfg["client_block_limit"]
    now = datetime.now()
    print(now.strftime("%b %d %H:%M:%S"))
    print()
    print(f"Pool name: {pool_name}")
    print(f"Port-overloading-factor: {1:>5}     Port block size:  {block_size}")
    print(f"Max port blocks per host: {max_blocks:>4}     Port block active timeout:    0")
    if per_host:
        print(f"Used/total port blocks per host: {used_blocks}/{max_blocks}")
    else:
        print(f"Used/total port blocks: {used_blocks}/{total_blocks}")
    if enhanced:
        util_pct = (used_blocks / total_blocks * 100) if total_blocks > 0 else 0
        print(f"Pool utilization: {util_pct:.1f}%")
    base_hdr = f"{'Host_IP':<30}{'External_IP':<31}{'Port_Block':>12}{'Ports_Used/':>18}{'Block_State/':>17}"
    base_sub = f"{'':<30}{'':<31}{'Range':>12}{'Ports_Total':>18}{'Left_Time(s)':>17}"
    if enhanced:
        base_hdr += f"  {'Util%':>6}  {'Subscriber_ID':<16}  {'Protocol_Breakdown'}"
        base_sub += f"  {'':>6}  {'':>16}  {''}"
    print(base_hdr)
    print(base_sub)


def print_pba_rows(entries: list[dict], mapping_index,
                   block_size: int, enhanced: bool = False):
    """Print PBA entry rows sorted by external_ip then port_start."""
    entries.sort(key=lambda e: (e["external_ip"], e["port_start"]))
    for entry in entries:
        port_range = f"{entry['port_start']}-{entry['port_end']}"
        ports_used = count_ports_used(
            entry["client_ip"], entry["external_ip"], entry["port_start"], entry["port_end"], mapping_index
        )
        state = determine_block_state(ports_used, entry["ttl"])
        ttl_str = "-" if entry["ttl"] == 0 else str(entry["ttl"])
        ports_str = "-" if ports_used is None else str(ports_used)
        line = (
            f"{entry['client_ip']:<30}"
            f"{entry['external_ip']:<31}"
            f"{port_range:>12}"
            f"{ports_str:>12}/{block_size}*1"
            f"{'':>4}{state}/{ttl_str}"
        )
        if enhanced:
            proto_counts = count_ports_by_protocol(
                entry["client_ip"], entry["external_ip"], entry["port_start"], entry["port_end"], mapping_index
            )
            proto_str = " ".join(f"{proto}:{cnt}" for proto, cnt in sorted(proto_counts.items())) if proto_counts else "-"
            sub_id = entry.get("subscriber_id", "-")
            if ports_used is None:
                line += f"  {'-':>6}  {sub_id:<16}  {proto_str}"
            else:
                util_pct = (ports_used / block_size * 100) if block_size > 0 else 0
                line += f"  {util_pct:>5.1f}%  {sub_id:<16}  {proto_str}"
        print(line)


def print_enhanced_host_footer(host_ip: str, entries: list[dict],
                               client_mapping_index, pool_cfg: dict):
    """Print enhanced per-host summary footer."""
    block_size = pool_cfg["block_size"]
    max_blocks = pool_cfg["client_block_limit"]
    num_blocks = len(entries)

    total_capacity = num_blocks * block_size
    print()
    print(f"  --- Enhanced Host Summary for {host_ip} ---")
    if client_mapping_index is not None:
        total_ports = 0
        proto_totals: dict[str, int] = defaultdict(int)
        for entry in entries:
            for m in client_mapping_index.get(host_ip, []):
                if entry["external_ip"] == m["translation_ip"] and entry["port_start"] <= m["translation_port"] <= entry["port_end"]:
                    total_ports += 1
                    proto_totals[m.get("protocol", "?")] += 1
        util_pct = (total_ports / total_capacity * 100) if total_capacity > 0 else 0
        print(f"  Total ports in use:    {total_ports:>6}  /  {total_capacity} capacity")
        print(f"  Overall utilization:   {util_pct:>5.1f}%")
    else:
        print("  Port utilization:      (unavailable in fast mode)")
    print(f"  Blocks allocated:      {num_blocks:>6}  /  {max_blocks} max")
    print(f"  Blocks remaining:      {max(0, max_blocks - num_blocks):>6}")
    if client_mapping_index is not None and proto_totals:
        proto_str = "  ".join(f"{proto}: {cnt}" for proto, cnt in sorted(proto_totals.items()))
        print(f"  Protocol totals:       {proto_str}")
    ext_ips = sorted(set(e["external_ip"] for e in entries))
    print(f"  External IPs:          {', '.join(ext_ips)}")


def print_enhanced_pool_footer(entries: list[dict], client_mapping_index,
                               pool_cfg: dict, pool_name: str, total_blocks: int, top_n: int = 10):
    """Print enhanced per-pool summary footer with top subscribers and IP distribution."""
    block_size = pool_cfg["block_size"]

    client_stats: dict[str, dict] = {}
    for entry in entries:
        cip = entry["client_ip"]
        if cip not in client_stats:
            client_stats[cip] = {"blocks": 0, "ports": 0, "external_ips": set()}
        client_stats[cip]["blocks"] += 1
        client_stats[cip]["external_ips"].add(entry["external_ip"])
        if client_mapping_index is not None:
            for m in client_mapping_index.get(cip, []):
                if entry["external_ip"] == m["translation_ip"] and entry["port_start"] <= m["translation_port"] <= entry["port_end"]:
                    client_stats[cip]["ports"] += 1

    unique_clients = len(client_stats)
    total_blocks_used = len(entries)
    avg_blocks = total_blocks_used / unique_clients if unique_clients > 0 else 0
    total_capacity = total_blocks * block_size
    pool_util_pct = (total_blocks_used / total_blocks * 100) if total_blocks > 0 else 0

    print()
    print(f"  --- Enhanced Pool Summary: {pool_name} ---")
    print(f"  Unique clients:        {unique_clients:>6}")
    print(f"  Total blocks used:     {total_blocks_used:>6}  /  {total_blocks} total  ({pool_util_pct:.1f}%)")
    if client_mapping_index is not None:
        total_ports = sum(s["ports"] for s in client_stats.values())
        util_pct = (total_ports / total_capacity * 100) if total_capacity > 0 else 0
        print(f"  Total ports in use:    {total_ports:>6}  /  {total_capacity} capacity  ({util_pct:.1f}%)")
    print(f"  Avg blocks per client: {avg_blocks:>6.1f}")

    if client_mapping_index is not None:
        top_by_ports = sorted(client_stats.items(), key=lambda x: x[1]["ports"], reverse=True)[:top_n]
        print(f"\n  Top {min(top_n, len(top_by_ports))} subscribers by port usage:")
        print(f"    {'Client_IP':<20} {'Ports':>8} {'Blocks':>8} {'Util%':>8}  {'External_IPs'}")
        for cip, stats in top_by_ports:
            cap = stats["blocks"] * block_size
            u = (stats["ports"] / cap * 100) if cap > 0 else 0
            ext_str = ", ".join(sorted(stats["external_ips"]))
            print(f"    {cip:<20} {stats['ports']:>8} {stats['blocks']:>8} {u:>7.1f}%  {ext_str}")

    top_by_blocks = sorted(client_stats.items(), key=lambda x: x[1]["blocks"], reverse=True)[:top_n]
    print(f"\n  Top {min(top_n, len(top_by_blocks))} subscribers by block count:")
    print(f"    {'Client_IP':<20} {'Blocks':>8} {'Ports':>8} {'Util%':>8}")
    for cip, stats in top_by_blocks:
        cap = stats["blocks"] * block_size
        if client_mapping_index is not None:
            u = (stats["ports"] / cap * 100) if cap > 0 else 0
            print(f"    {cip:<20} {stats['blocks']:>8} {stats['ports']:>8} {u:>7.1f}%")
        else:
            print(f"    {cip:<20} {stats['blocks']:>8} {'-':>8} {'-':>8}")

    ext_ip_counts: dict[str, int] = defaultdict(int)
    for entry in entries:
        ext_ip_counts[entry["external_ip"]] += 1
    print(f"\n  External IP distribution ({len(ext_ip_counts)} IPs):")
    print(f"    {'External_IP':<20} {'Blocks':>8} {'Alloc%':>8}")
    for eip, cnt in sorted(ext_ip_counts.items(), key=lambda x: x[1], reverse=True):
        blocks_per_ip = (65535 - 1024 + 1) // block_size
        alloc_pct = (cnt / blocks_per_ip * 100) if blocks_per_ip > 0 else 0
        print(f"    {eip:<20} {cnt:>8} {alloc_pct:>7.1f}%")


def show_host(host_ip: str, pba_entries: list[dict], mapping_index: dict[tuple[str, str], list[dict]],
              client_mapping_index: dict[str, list[dict]], pools: dict,
              enhanced: bool = False):
    """Display output for a single host IP."""
    host_entries = [e for e in pba_entries if e["client_ip"] == host_ip]
    if not host_entries:
        print(f"No port block allocations found for {host_ip}")
        return

    pool_name, pool_cfg = find_pool_for_ip(host_entries[0]["external_ip"], pools)
    if not pool_cfg:
        pool_cfg = unknown_pool_cfg(host_entries)
        pool_name = "Unknown"

    total_blocks = calc_total_port_blocks(pool_cfg)
    print_pool_header(pool_name, pool_cfg, len(host_entries), total_blocks, per_host=True,
                      enhanced=enhanced)
    print_pba_rows(host_entries, mapping_index, pool_cfg["block_size"], enhanced=enhanced)
    if enhanced:
        print_enhanced_host_footer(host_ip, host_entries, client_mapping_index, pool_cfg)


def show_pool(pool_name: str, pba_entries: list[dict], mapping_index: dict[tuple[str, str], list[dict]],
              client_mapping_index: dict[str, list[dict]], pools: dict,
              enhanced: bool = False):
    """Display output for all entries in a specific pool."""
    pool_cfg = pools.get(pool_name)
    if not pool_cfg:
        print(f"Pool '{pool_name}' not found. Available pools:")
        for name in sorted(pools.keys()):
            print(f"  {name}")
        return

    pool_entries = filter_entries_by_pool(pba_entries, pool_name, pools)
    if not pool_entries:
        print(f"No port block allocations found for pool {pool_name}")
        return

    total_blocks = calc_total_port_blocks(pool_cfg)
    print_pool_header(pool_name, pool_cfg, len(pool_entries), total_blocks, enhanced=enhanced)
    print_pba_rows(pool_entries, mapping_index, pool_cfg["block_size"], enhanced=enhanced)
    if enhanced:
        print_enhanced_pool_footer(pool_entries, client_mapping_index, pool_cfg, pool_name, total_blocks)


def show_all(pba_entries: list[dict], mapping_index: dict[tuple[str, str], list[dict]],
             client_mapping_index: dict[str, list[dict]], pools: dict,
             enhanced: bool = False):
    """Show port block info grouped by pool."""
    # Group entries by pool
    pool_groups = defaultdict(list)
    for entry in pba_entries:
        found_pool, _ = find_pool_for_ip(entry["external_ip"], pools)
        pool_groups[found_pool or "Unknown"].append(entry)

    first = True
    for pool_name in sorted(pool_groups.keys()):
        if not first:
            print()
        first = False
        entries = pool_groups[pool_name]
        pool_cfg = pools.get(pool_name) or unknown_pool_cfg(entries)
        total_blocks = calc_total_port_blocks(pool_cfg)
        print_pool_header(pool_name, pool_cfg, len(entries), total_blocks, enhanced=enhanced)
        print_pba_rows(entries, mapping_index, pool_cfg["block_size"], enhanced=enhanced)
        if enhanced:
            print_enhanced_pool_footer(entries, client_mapping_index, pool_cfg, pool_name, total_blocks)


def show_summary(pba_entries: list[dict], pools: dict, enhanced: bool = False):
    """Show a summary of PBA usage across all pools."""
    blocks_used: dict[str, int] = defaultdict(int)
    client_ips: dict[str, set[str]] = defaultdict(set)

    for entry in pba_entries:
        pool_name, _ = find_pool_for_ip(entry["external_ip"], pools)
        if not pool_name:
            pool_name = "Unknown"
        blocks_used[pool_name] += 1
        client_ips[pool_name].add(entry["client_ip"])

    now = datetime.now()
    print(now.strftime("%b %d %H:%M:%S"))
    print()

    if enhanced:
        print(f"{'Pool Name':<45} {'Clients':>8} {'Blocks Used':>12} {'Total Blks':>11} {'Block Size':>11} {'Max Blks':>9} {'Pool%':>7} {'Avg Blk/Client':>15}")
        print("-" * 122)
    else:
        print(f"{'Pool Name':<45} {'Clients':>8} {'Blocks Used':>12} {'Block Size':>11} {'Max Blocks':>11}")
        print("-" * 90)

    for pname in sorted(blocks_used.keys()):
        num_clients = len(client_ips[pname])
        num_blocks = blocks_used[pname]
        pool_cfg = pools.get(pname, {})
        block_size = pool_cfg.get("block_size", "?")
        max_blk = pool_cfg.get("client_block_limit", "?")
        if enhanced:
            total_blocks = calc_total_port_blocks(pool_cfg) if pool_cfg.get("addresses") else 0
            pool_pct = (num_blocks / total_blocks * 100) if total_blocks > 0 else 0
            avg_blk = num_blocks / num_clients if num_clients > 0 else 0
            print(
                f"{pname:<45} "
                f"{num_clients:>8} "
                f"{num_blocks:>12} "
                f"{total_blocks:>11} "
                f"{block_size:>11} "
                f"{max_blk:>9} "
                f"{pool_pct:>6.1f}% "
                f"{avg_blk:>15.1f}"
            )
        else:
            print(
                f"{pname:<45} "
                f"{num_clients:>8} "
                f"{num_blocks:>12} "
                f"{block_size:>11} "
                f"{max_blk:>11}"
            )


# ---------------------------------------------------------------------------
# JSON output builders
# ---------------------------------------------------------------------------

def build_block_data(entry: dict, mapping_index, block_size: int) -> dict:
    """Build a dict for a single PBA block entry."""
    ports_used = count_ports_used(
        entry["client_ip"], entry["external_ip"], entry["port_start"], entry["port_end"], mapping_index
    )
    proto_counts = count_ports_by_protocol(
        entry["client_ip"], entry["external_ip"], entry["port_start"], entry["port_end"], mapping_index
    )
    state = determine_block_state(ports_used, entry["ttl"])
    util_pct = (ports_used / block_size * 100) if (ports_used is not None and block_size > 0) else None
    return {
        "client_ip": entry["client_ip"],
        "external_ip": entry["external_ip"],
        "port_start": entry["port_start"],
        "port_end": entry["port_end"],
        "subscriber_id": entry.get("subscriber_id", ""),
        "ttl": entry["ttl"],
        "ports_used": ports_used,
        "ports_total": block_size,
        "utilization_pct": round(util_pct, 1) if util_pct is not None else None,
        "block_state": state,
        "protocol_breakdown": proto_counts,
    }


def build_pool_data(pool_name: str, pool_cfg: dict, entries: list[dict],
                    mapping_index, total_blocks: int) -> dict:
    """Build a dict for a pool with all its blocks and enhanced stats."""
    block_size = pool_cfg["block_size"]
    has_inbound = mapping_index is not None
    blocks = [build_block_data(e, mapping_index, block_size) for e in
              sorted(entries, key=lambda e: (e["external_ip"], e["port_start"]))]

    client_stats: dict[str, dict] = {}
    for block in blocks:
        cip = block["client_ip"]
        if cip not in client_stats:
            client_stats[cip] = {"blocks": 0, "ports_used": 0, "external_ips": set()}
        client_stats[cip]["blocks"] += 1
        if block["ports_used"] is not None:
            client_stats[cip]["ports_used"] += block["ports_used"]
        client_stats[cip]["external_ips"].add(block["external_ip"])

    total_ports = sum(b["ports_used"] for b in blocks if b["ports_used"] is not None)
    total_capacity = total_blocks * block_size
    pool_util_pct = (len(entries) / total_blocks * 100) if total_blocks > 0 else 0
    port_util_pct = round((total_ports / total_capacity * 100), 1) if (total_capacity > 0 and has_inbound) else None

    ext_ip_dist: dict[str, int] = defaultdict(int)
    for e in entries:
        ext_ip_dist[e["external_ip"]] += 1

    clients = []
    for cip, stats in sorted(client_stats.items()):
        cap = stats["blocks"] * block_size
        clients.append({
            "client_ip": cip,
            "blocks": stats["blocks"],
            "ports_used": stats["ports_used"] if has_inbound else None,
            "utilization_pct": round((stats["ports_used"] / cap * 100) if cap > 0 else 0, 1) if has_inbound else None,
            "external_ips": sorted(stats["external_ips"]),
        })

    return {
        "pool_name": pool_name,
        "block_size": block_size,
        "client_block_limit": pool_cfg["client_block_limit"],
        "blocks_used": len(entries),
        "blocks_total": total_blocks,
        "pool_utilization_pct": round(pool_util_pct, 1),
        "total_ports_used": total_ports if has_inbound else None,
        "total_port_capacity": total_capacity,
        "port_utilization_pct": port_util_pct,
        "unique_clients": len(client_stats),
        "avg_blocks_per_client": round(len(entries) / len(client_stats), 1) if client_stats else 0,
        "blocks": blocks,
        "clients": clients,
        "external_ip_distribution": dict(sorted(ext_ip_dist.items(), key=lambda x: x[1], reverse=True)),
    }


def json_host(host_ip: str, pba_entries: list[dict], mapping_index, pools: dict) -> dict:
    """Build JSON data for a single host IP."""
    host_entries = [e for e in pba_entries if e["client_ip"] == host_ip]
    if not host_entries:
        return {"error": f"No port block allocations found for {host_ip}"}

    pool_name, pool_cfg = find_pool_for_ip(host_entries[0]["external_ip"], pools)
    if not pool_cfg:
        pool_cfg = unknown_pool_cfg(host_entries)
        pool_name = "Unknown"

    has_inbound = mapping_index is not None
    block_size = pool_cfg["block_size"]
    blocks = [build_block_data(e, mapping_index, block_size) for e in
              sorted(host_entries, key=lambda e: (e["external_ip"], e["port_start"]))]

    total_ports = sum(b["ports_used"] for b in blocks if b["ports_used"] is not None)
    total_capacity = len(host_entries) * block_size
    util_pct = round((total_ports / total_capacity * 100), 1) if (total_capacity > 0 and has_inbound) else None

    proto_totals: dict[str, int] = defaultdict(int)
    for b in blocks:
        for proto, cnt in b["protocol_breakdown"].items():
            proto_totals[proto] += cnt

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host_ip": host_ip,
        "pool_name": pool_name,
        "block_size": block_size,
        "client_block_limit": pool_cfg["client_block_limit"],
        "blocks_allocated": len(host_entries),
        "blocks_remaining": max(0, pool_cfg["client_block_limit"] - len(host_entries)),
        "total_ports_used": total_ports if has_inbound else None,
        "total_port_capacity": total_capacity,
        "utilization_pct": util_pct,
        "protocol_totals": dict(proto_totals),
        "external_ips": sorted(set(e["external_ip"] for e in host_entries)),
        "blocks": blocks,
    }


def json_pool(pool_name: str, pba_entries: list[dict], mapping_index: dict[tuple[str, str], list[dict]], pools: dict) -> dict:
    """Build JSON data for a specific pool."""
    pool_cfg = pools.get(pool_name)
    if not pool_cfg:
        return {"error": f"Pool '{pool_name}' not found", "available_pools": sorted(pools.keys())}

    pool_entries = filter_entries_by_pool(pba_entries, pool_name, pools)
    if not pool_entries:
        return {"error": f"No port block allocations found for pool {pool_name}"}

    total_blocks = calc_total_port_blocks(pool_cfg)
    result = build_pool_data(pool_name, pool_cfg, pool_entries, mapping_index, total_blocks)
    result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return result


def json_xlated_ip(xlated_ip: str, pba_entries: list[dict], mapping_index: dict[tuple[str, str], list[dict]], pools: dict) -> dict:
    """Build JSON data filtered by translated IP."""
    filtered = [e for e in pba_entries if e["external_ip"] == xlated_ip]
    if not filtered:
        return {"error": f"No port block allocations found for translated IP {xlated_ip}"}

    pool_name, pool_cfg = find_pool_for_ip(xlated_ip, pools)
    if not pool_cfg:
        pool_cfg = unknown_pool_cfg(filtered)
        pool_name = "Unknown"

    total_blocks = calc_total_port_blocks(pool_cfg)
    result = build_pool_data(pool_name, pool_cfg, filtered, mapping_index, total_blocks)
    result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result["filtered_by"] = xlated_ip
    return result


def json_all(pba_entries: list[dict], mapping_index: dict[tuple[str, str], list[dict]], pools: dict) -> dict:
    """Build JSON data for all pools."""
    pool_groups: dict[str, list[dict]] = defaultdict(list)
    for entry in pba_entries:
        found_pool, _ = find_pool_for_ip(entry["external_ip"], pools)
        pool_groups[found_pool or "Unknown"].append(entry)

    pool_data = []
    for pool_name in sorted(pool_groups.keys()):
        entries = pool_groups[pool_name]
        pool_cfg = pools.get(pool_name) or unknown_pool_cfg(entries)
        total_blocks = calc_total_port_blocks(pool_cfg)
        pool_data.append(build_pool_data(pool_name, pool_cfg, entries, mapping_index, total_blocks))

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pools": pool_data,
    }


def show_fast_summary(pools: dict, tmctl_stats: dict, client_summary: dict, enhanced: bool = False):
    """
    Summary using tmctl (instant). Per-pool client count is unavailable in this
    path; total unique subscribers across all pools is shown at the bottom.
    Only pools with at least one active block are displayed.
    """
    now = datetime.now()
    print(now.strftime("%b %d %H:%M:%S"))
    print()

    if enhanced:
        print(f"{'Pool Name':<45} {'Clients':>8} {'Blocks Used':>12} {'Total Blks':>11} {'Block Size':>11} {'Max Blks':>9} {'Pool%':>7}")
        print("-" * 107)
    else:
        print(f"{'Pool Name':<45} {'Clients':>8} {'Blocks Used':>12} {'Block Size':>11} {'Max Blocks':>11}")
        print("-" * 90)

    active_pools = {n: d for n, d in tmctl_stats.items() if d["active_port_blocks"] > 0}
    for pool_name in sorted(active_pools.keys()):
        ts = active_pools[pool_name]
        pool_cfg = pools.get(pool_name, {})
        blocks_used = ts["active_port_blocks"]
        total_blocks = ts["total_port_blocks"]
        block_size = pool_cfg.get("block_size", "?")
        max_blk = pool_cfg.get("client_block_limit", "?")
        if enhanced:
            pool_pct = (blocks_used / total_blocks * 100) if total_blocks > 0 else 0
            print(f"{pool_name:<45} {'-':>8} {blocks_used:>12} {total_blocks:>11} {block_size:>11} {max_blk:>9} {pool_pct:>6.1f}%")
        else:
            print(f"{pool_name:<45} {'-':>8} {blocks_used:>12} {block_size:>11} {max_blk:>11}")

    if not active_pools:
        print("(no active port blocks found)")

    print()
    print(f"Total unique subscribers (all pools): {len(client_summary)}")
    print("(Per-pool client count unavailable in fast mode; omit --fast for full breakdown)")


def json_fast_summary(pools: dict, tmctl_stats: dict, client_summary: dict) -> dict:
    """
    JSON summary using tmctl data. Per-pool client breakdown is unavailable;
    total unique subscribers is included at the top level.
    Consumers should check fast_mode=true and handle clients=null.
    """
    pool_summaries = []
    for pool_name in sorted(tmctl_stats.keys()):
        ts = tmctl_stats[pool_name]
        pool_cfg = pools.get(pool_name, {})
        blocks_used = ts["active_port_blocks"]
        total_blocks = ts["total_port_blocks"]
        pool_pct = round((blocks_used / total_blocks * 100), 1) if total_blocks > 0 else 0
        pool_summaries.append({
            "pool_name": pool_name,
            "clients": None,
            "blocks_used": blocks_used,
            "blocks_total": total_blocks,
            "block_size": pool_cfg.get("block_size"),
            "client_block_limit": pool_cfg.get("client_block_limit"),
            "pool_utilization_pct": pool_pct,
            "avg_blocks_per_client": None,
        })

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "fast_mode": True,
        "total_unique_subscribers": len(client_summary),
        "pools": pool_summaries,
    }


def json_summary(pba_entries: list[dict], pools: dict) -> dict:
    """Build JSON data for the summary view."""
    blocks_used: dict[str, int] = defaultdict(int)
    client_ips_map: dict[str, set[str]] = defaultdict(set)

    for entry in pba_entries:
        pool_name, _ = find_pool_for_ip(entry["external_ip"], pools)
        if not pool_name:
            pool_name = "Unknown"
        blocks_used[pool_name] += 1
        client_ips_map[pool_name].add(entry["client_ip"])

    pool_summaries = []
    for pname in sorted(blocks_used.keys()):
        num_clients = len(client_ips_map[pname])
        num_blocks = blocks_used[pname]
        pool_cfg = pools.get(pname, {})
        total_blocks = calc_total_port_blocks(pool_cfg) if pool_cfg.get("addresses") else 0
        pool_pct = (num_blocks / total_blocks * 100) if total_blocks > 0 else 0
        avg_blk = num_blocks / num_clients if num_clients > 0 else 0
        pool_summaries.append({
            "pool_name": pname,
            "clients": num_clients,
            "blocks_used": num_blocks,
            "blocks_total": total_blocks,
            "block_size": pool_cfg.get("block_size", None),
            "client_block_limit": pool_cfg.get("client_block_limit", None),
            "pool_utilization_pct": round(pool_pct, 1),
            "avg_blocks_per_client": round(avg_blk, 1),
        })

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pools": pool_summaries,
    }


def main():
    script_start = time.time()
    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Starting CGNAT PBA Stats script (lsndb)", file=sys.stderr)

    parser = argparse.ArgumentParser(
        description="Query F5 BIG-IP CGNAT PBA stats"
    )
    parser.add_argument("--bigip", required=True, metavar="HOST",
                        help="BIG-IP hostname or IP address")
    parser.add_argument("--port", default="22", metavar="PORT",
                        help="SSH port (default: 22)")
    parser.add_argument("--user", metavar="USERNAME",
                        help="SSH username; prompts for password unless --key-file is set")
    parser.add_argument("--key-file", metavar="FILE",
                        help="SSH private key file for publickey authentication")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("host_ip", nargs="?", help="Client/subscriber IP to query")
    group.add_argument("--pool", metavar="POOL_NAME", help="Show all port blocks for a specific pool")
    group.add_argument("--xlated-ip", metavar="IP", help="Filter by translated/external IP address")
    group.add_argument("--all", action="store_true", help="Show all client port blocks")
    group.add_argument("--summary", action="store_true", help="Show PBA usage summary")

    parser.add_argument("--enhanced", action="store_true",
                        help="Show enhanced stats (utilization %%, protocol breakdown, top subscribers, etc.)")
    parser.add_argument("--json", action="store_true",
                        help="Output data as JSON instead of text")
    parser.add_argument("--no-host-key-check", action="store_true",
                        help="Disable SSH host key verification (insecure)")
    parser.add_argument("--fast", action="store_true",
                        help=(
                            "Fast mode: skip lsndb list inbound (port-in-use data omitted). "
                            "For --summary, uses tmctl instead of lsndb list pba entirely. "
                            "Dramatically faster on deployments with 10k+ subscribers."
                        ))

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
        with Timer("SSH connection establishment"):
            ssh_connect(args.bigip, int(args.port), username=username,
                        password=password, key_filename=key_file,
                        no_host_key_check=args.no_host_key_check)
    except Exception as e:
        print(f"ERROR: Cannot connect to {args.bigip}:{args.port} - {e}", file=sys.stderr)
        sys.exit(1)

    enhanced = args.enhanced
    use_json = args.json
    fast_mode = args.fast

    # --summary --fast: bypass lsndb entirely using tmctl + lsndb summary pba
    if args.summary and fast_mode:
        with Timer("Fetching pool configurations"):
            pools = get_pool_configs()
        with Timer("Fetching tmctl pool stats (fast path)"):
            tmctl_stats = get_tmctl_pool_stats()
        if not tmctl_stats:
            # tmctl unavailable — fall back to normal summary path
            with Timer("Fetching PBA entries (tmctl unavailable, falling back)"):
                pba_entries = get_pba_entries()
            if not pba_entries:
                out = {"error": "No PBA entries found on the BIG-IP."}
                print(json.dumps(out) if use_json else out["error"])
                sys.exit(0)
            result = json_summary(pba_entries, pools)
            if use_json:
                print(json.dumps(result, separators=(",", ":")))
            else:
                show_summary(pba_entries, pools, enhanced=enhanced)
        else:
            with Timer("Fetching subscriber count summary"):
                client_summary = get_pba_client_summary()
            if use_json:
                print(json.dumps(json_fast_summary(pools, tmctl_stats, client_summary), separators=(",", ":")))
            else:
                show_fast_summary(pools, tmctl_stats, client_summary, enhanced=enhanced)
        script_end = time.time()
        print(f"\n[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Script completed in {script_end - script_start:.3f}s", file=sys.stderr)
        return

    with Timer("Fetching pool configurations"):
        pools = get_pool_configs()

    with Timer("Fetching PBA entries"):
        pba_entries = get_pba_entries()

    if not pba_entries:
        if use_json:
            print(json.dumps({"error": "No PBA entries found on the BIG-IP."}))
        else:
            print("No PBA entries found on the BIG-IP.")
        sys.exit(0)

    # --summary (normal): no inbound needed
    if args.summary:
        with Timer("Processing and displaying summary"):
            if use_json:
                print(json.dumps(json_summary(pba_entries, pools), separators=(",", ":")))
            else:
                show_summary(pba_entries, pools, enhanced=enhanced)
        script_end = time.time()
        print(f"\n[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Script completed in {script_end - script_start:.3f}s", file=sys.stderr)
        return

    # All other modes: optionally fetch inbound mappings
    if fast_mode:
        mapping_index = None
        client_mapping_index = None
        if not use_json:
            print("[Fast mode: port-in-use data omitted. Run without --fast for full stats.]")
            print()
    else:
        with Timer("Fetching inbound mappings (port usage)"):
            mappings = get_inbound_mappings()
        mapping_index, client_mapping_index = build_mapping_indexes(mappings)

    if use_json:
        if args.pool:
            result = json_pool(args.pool, pba_entries, mapping_index, pools)
        elif args.xlated_ip:
            result = json_xlated_ip(args.xlated_ip, pba_entries, mapping_index, pools)
        elif args.all:
            result = json_all(pba_entries, mapping_index, pools)
        else:
            result = json_host(args.host_ip, pba_entries, mapping_index, pools)
        if fast_mode:
            result["fast_mode"] = True
        print(json.dumps(result, separators=(",", ":")))
    else:
        with Timer("Processing and displaying results"):
            if args.pool:
                show_pool(args.pool, pba_entries, mapping_index, client_mapping_index, pools, enhanced=enhanced)
            elif args.xlated_ip:
                filtered = [e for e in pba_entries if e["external_ip"] == args.xlated_ip]
                if not filtered:
                    print(f"No port block allocations found for translated IP {args.xlated_ip}")
                else:
                    pool_name, pool_cfg = find_pool_for_ip(args.xlated_ip, pools)
                    if not pool_cfg:
                        pool_cfg = unknown_pool_cfg(filtered)
                        pool_name = "Unknown"
                    total_blocks = calc_total_port_blocks(pool_cfg)
                    print_pool_header(pool_name, pool_cfg, len(filtered), total_blocks,
                                      enhanced=enhanced)
                    print_pba_rows(filtered, mapping_index, pool_cfg["block_size"], enhanced=enhanced)
                    if enhanced:
                        print_enhanced_pool_footer(filtered, client_mapping_index, pool_cfg, pool_name,
                                                   total_blocks)
            elif args.all:
                show_all(pba_entries, mapping_index, client_mapping_index, pools, enhanced=enhanced)
            else:
                show_host(args.host_ip, pba_entries, mapping_index, client_mapping_index, pools, enhanced=enhanced)

    script_end = time.time()
    total_duration = script_end - script_start
    print(f"\n[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Script completed in {total_duration:.3f}s", file=sys.stderr)


if __name__ == "__main__":
    main()
