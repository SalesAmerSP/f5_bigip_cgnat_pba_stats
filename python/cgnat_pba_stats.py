#!/usr/bin/env python3
"""
CGNAT PBA Stats - Query per-subscriber port block allocations on F5 BIG-IP via SSH
using lsndb and tmsh commands.

Usage:
    python cgnat_pba_stats.py --bigip 10.0.0.1 <host_ip>
    python cgnat_pba_stats.py --bigip bigip.example.com --pool POOL-DMA-FL-Miami
    python cgnat_pba_stats.py --bigip bigip.example.com --all
    python cgnat_pba_stats.py --bigip bigip.example.com --summary
"""

import argparse
import getpass
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

import paramiko


SSH_CLIENT: paramiko.SSHClient | None = None


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


def count_ports_used(client_ip: str, port_start: int, port_end: int, mappings: list[dict]) -> int:
    """Count how many inbound mapping ports fall within a port block for a client."""
    count = 0
    for m in mappings:
        if m["client_ip"] == client_ip and port_start <= m["translation_port"] <= port_end:
            count += 1
    return count


def count_ports_by_protocol(client_ip: str, port_start: int, port_end: int,
                            mappings: list[dict]) -> dict[str, int]:
    """Count ports used per protocol within a port block for a client."""
    proto_counts: dict[str, int] = defaultdict(int)
    for m in mappings:
        if m["client_ip"] == client_ip and port_start <= m["translation_port"] <= port_end:
            proto_counts[m.get("protocol", "?")] += 1
    return dict(proto_counts)


def determine_block_state(ports_used: int, ttl: int, block_idle_timeout: int = 0) -> str:
    """Determine block state:
    Active    - block allocated and ports in use
    Query     - block allocated, zero ports in use but TTL still running
    Inactive  - block expired or depleted
    """
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


def print_pba_rows(entries: list[dict], mappings: list[dict], block_size: int,
                   enhanced: bool = False):
    """Print PBA entry rows sorted by external_ip then port_start."""
    entries.sort(key=lambda e: (e["external_ip"], e["port_start"]))
    for entry in entries:
        port_range = f"{entry['port_start']}-{entry['port_end']}"
        ports_used = count_ports_used(entry["client_ip"], entry["port_start"], entry["port_end"], mappings)
        state = determine_block_state(ports_used, entry["ttl"])
        ttl_str = "-" if entry["ttl"] == 0 else str(entry["ttl"])
        line = (
            f"{entry['client_ip']:<30}"
            f"{entry['external_ip']:<31}"
            f"{port_range:>12}"
            f"{ports_used:>12}/{block_size}*1"
            f"{'':>4}{state}/{ttl_str}"
        )
        if enhanced:
            util_pct = (ports_used / block_size * 100) if block_size > 0 else 0
            proto_counts = count_ports_by_protocol(
                entry["client_ip"], entry["port_start"], entry["port_end"], mappings
            )
            proto_str = " ".join(f"{proto}:{cnt}" for proto, cnt in sorted(proto_counts.items())) if proto_counts else "-"
            sub_id = entry.get("subscriber_id", "-")
            line += f"  {util_pct:>5.1f}%  {sub_id:<16}  {proto_str}"
        print(line)


def print_enhanced_host_footer(host_ip: str, entries: list[dict], mappings: list[dict],
                               pool_cfg: dict):
    """Print enhanced per-host summary footer."""
    block_size = pool_cfg["block_size"]
    max_blocks = pool_cfg["client_block_limit"]
    num_blocks = len(entries)
    total_capacity = num_blocks * block_size

    total_ports = 0
    proto_totals: dict[str, int] = defaultdict(int)
    for entry in entries:
        for m in mappings:
            if m["client_ip"] == host_ip and entry["port_start"] <= m["translation_port"] <= entry["port_end"]:
                total_ports += 1
                proto_totals[m.get("protocol", "?")] += 1

    util_pct = (total_ports / total_capacity * 100) if total_capacity > 0 else 0
    blocks_remaining = max(0, max_blocks - num_blocks)

    print()
    print(f"  --- Enhanced Host Summary for {host_ip} ---")
    print(f"  Total ports in use:    {total_ports:>6}  /  {total_capacity} capacity")
    print(f"  Overall utilization:   {util_pct:>5.1f}%")
    print(f"  Blocks allocated:      {num_blocks:>6}  /  {max_blocks} max")
    print(f"  Blocks remaining:      {blocks_remaining:>6}")
    if proto_totals:
        proto_str = "  ".join(f"{proto}: {cnt}" for proto, cnt in sorted(proto_totals.items()))
        print(f"  Protocol totals:       {proto_str}")
    ext_ips = sorted(set(e["external_ip"] for e in entries))
    print(f"  External IPs:          {', '.join(ext_ips)}")


def print_enhanced_pool_footer(entries: list[dict], mappings: list[dict], pool_cfg: dict,
                               pool_name: str, total_blocks: int, top_n: int = 10):
    """Print enhanced per-pool summary footer with top subscribers and IP distribution."""
    block_size = pool_cfg["block_size"]

    # Aggregate per-client stats
    client_stats: dict[str, dict] = {}
    for entry in entries:
        cip = entry["client_ip"]
        if cip not in client_stats:
            client_stats[cip] = {"blocks": 0, "ports": 0, "external_ips": set()}
        client_stats[cip]["blocks"] += 1
        client_stats[cip]["external_ips"].add(entry["external_ip"])
        for m in mappings:
            if m["client_ip"] == cip and entry["port_start"] <= m["translation_port"] <= entry["port_end"]:
                client_stats[cip]["ports"] += 1

    unique_clients = len(client_stats)
    total_blocks_used = len(entries)
    avg_blocks = total_blocks_used / unique_clients if unique_clients > 0 else 0
    total_ports = sum(s["ports"] for s in client_stats.values())
    total_capacity = total_blocks_used * block_size
    util_pct = (total_ports / total_capacity * 100) if total_capacity > 0 else 0
    pool_util_pct = (total_blocks_used / total_blocks * 100) if total_blocks > 0 else 0

    print()
    print(f"  --- Enhanced Pool Summary: {pool_name} ---")
    print(f"  Unique clients:        {unique_clients:>6}")
    print(f"  Total blocks used:     {total_blocks_used:>6}  /  {total_blocks} total  ({pool_util_pct:.1f}%)")
    print(f"  Total ports in use:    {total_ports:>6}  /  {total_capacity} capacity  ({util_pct:.1f}%)")
    print(f"  Avg blocks per client: {avg_blocks:>6.1f}")

    # Top N subscribers by port usage
    top_by_ports = sorted(client_stats.items(), key=lambda x: x[1]["ports"], reverse=True)[:top_n]
    print(f"\n  Top {min(top_n, len(top_by_ports))} subscribers by port usage:")
    print(f"    {'Client_IP':<20} {'Ports':>8} {'Blocks':>8} {'Util%':>8}  {'External_IPs'}")
    for cip, stats in top_by_ports:
        cap = stats["blocks"] * block_size
        u = (stats["ports"] / cap * 100) if cap > 0 else 0
        ext_str = ", ".join(sorted(stats["external_ips"]))
        print(f"    {cip:<20} {stats['ports']:>8} {stats['blocks']:>8} {u:>7.1f}%  {ext_str}")

    # Top N subscribers by block count
    top_by_blocks = sorted(client_stats.items(), key=lambda x: x[1]["blocks"], reverse=True)[:top_n]
    print(f"\n  Top {min(top_n, len(top_by_blocks))} subscribers by block count:")
    print(f"    {'Client_IP':<20} {'Blocks':>8} {'Ports':>8} {'Util%':>8}")
    for cip, stats in top_by_blocks:
        cap = stats["blocks"] * block_size
        u = (stats["ports"] / cap * 100) if cap > 0 else 0
        print(f"    {cip:<20} {stats['blocks']:>8} {stats['ports']:>8} {u:>7.1f}%")

    # External IP distribution
    ext_ip_counts: dict[str, int] = defaultdict(int)
    for entry in entries:
        ext_ip_counts[entry["external_ip"]] += 1
    print(f"\n  External IP distribution ({len(ext_ip_counts)} IPs):")
    print(f"    {'External_IP':<20} {'Blocks':>8} {'Alloc%':>8}")
    for eip, cnt in sorted(ext_ip_counts.items(), key=lambda x: x[1], reverse=True):
        blocks_per_ip = (65535 - 1024 + 1) // block_size
        alloc_pct = (cnt / blocks_per_ip * 100) if blocks_per_ip > 0 else 0
        print(f"    {eip:<20} {cnt:>8} {alloc_pct:>7.1f}%")


def show_host(host_ip: str, pba_entries: list[dict], mappings: list[dict], pools: dict,
              enhanced: bool = False):
    """Display output for a single host IP."""
    host_entries = [e for e in pba_entries if e["client_ip"] == host_ip]
    if not host_entries:
        print(f"No port block allocations found for {host_ip}")
        return

    pool_name, pool_cfg = find_pool_for_ip(host_entries[0]["external_ip"], pools)
    if not pool_cfg:
        pool_cfg = {"block_size": 256, "client_block_limit": 1, "addresses": []}
        pool_name = "Unknown"

    total_blocks = calc_total_port_blocks(pool_cfg)
    print_pool_header(pool_name, pool_cfg, len(host_entries), total_blocks, per_host=True,
                      enhanced=enhanced)
    print_pba_rows(host_entries, mappings, pool_cfg["block_size"], enhanced=enhanced)
    if enhanced:
        print_enhanced_host_footer(host_ip, host_entries, mappings, pool_cfg)


def show_pool(pool_name: str, pba_entries: list[dict], mappings: list[dict], pools: dict,
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
    print_pba_rows(pool_entries, mappings, pool_cfg["block_size"], enhanced=enhanced)
    if enhanced:
        print_enhanced_pool_footer(pool_entries, mappings, pool_cfg, pool_name, total_blocks)


def show_all(pba_entries: list[dict], mappings: list[dict], pools: dict,
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
        pool_cfg = pools.get(pool_name, {"block_size": 256, "client_block_limit": 1, "addresses": []})
        entries = pool_groups[pool_name]
        total_blocks = calc_total_port_blocks(pool_cfg)
        print_pool_header(pool_name, pool_cfg, len(entries), total_blocks, enhanced=enhanced)
        print_pba_rows(entries, mappings, pool_cfg["block_size"], enhanced=enhanced)
        if enhanced:
            print_enhanced_pool_footer(entries, mappings, pool_cfg, pool_name, total_blocks)


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

def build_block_data(entry: dict, mappings: list[dict], block_size: int) -> dict:
    """Build a dict for a single PBA block entry."""
    ports_used = count_ports_used(entry["client_ip"], entry["port_start"], entry["port_end"], mappings)
    proto_counts = count_ports_by_protocol(entry["client_ip"], entry["port_start"], entry["port_end"], mappings)
    state = determine_block_state(ports_used, entry["ttl"])
    util_pct = (ports_used / block_size * 100) if block_size > 0 else 0
    return {
        "client_ip": entry["client_ip"],
        "external_ip": entry["external_ip"],
        "port_start": entry["port_start"],
        "port_end": entry["port_end"],
        "subscriber_id": entry.get("subscriber_id", ""),
        "ttl": entry["ttl"],
        "ports_used": ports_used,
        "ports_total": block_size,
        "utilization_pct": round(util_pct, 1),
        "block_state": state,
        "protocol_breakdown": proto_counts,
    }


def build_pool_data(pool_name: str, pool_cfg: dict, entries: list[dict],
                    mappings: list[dict], total_blocks: int) -> dict:
    """Build a dict for a pool with all its blocks and enhanced stats."""
    block_size = pool_cfg["block_size"]
    blocks = [build_block_data(e, mappings, block_size) for e in
              sorted(entries, key=lambda e: (e["external_ip"], e["port_start"]))]

    # Aggregate per-client stats
    client_stats: dict[str, dict] = {}
    for block in blocks:
        cip = block["client_ip"]
        if cip not in client_stats:
            client_stats[cip] = {"blocks": 0, "ports_used": 0, "external_ips": set()}
        client_stats[cip]["blocks"] += 1
        client_stats[cip]["ports_used"] += block["ports_used"]
        client_stats[cip]["external_ips"].add(block["external_ip"])

    total_ports = sum(b["ports_used"] for b in blocks)
    total_capacity = len(entries) * block_size
    pool_util_pct = (len(entries) / total_blocks * 100) if total_blocks > 0 else 0
    port_util_pct = (total_ports / total_capacity * 100) if total_capacity > 0 else 0

    # External IP distribution
    ext_ip_dist: dict[str, int] = defaultdict(int)
    for e in entries:
        ext_ip_dist[e["external_ip"]] += 1

    # Build per-client summary
    clients = []
    for cip, stats in sorted(client_stats.items()):
        cap = stats["blocks"] * block_size
        clients.append({
            "client_ip": cip,
            "blocks": stats["blocks"],
            "ports_used": stats["ports_used"],
            "utilization_pct": round((stats["ports_used"] / cap * 100) if cap > 0 else 0, 1),
            "external_ips": sorted(stats["external_ips"]),
        })

    return {
        "pool_name": pool_name,
        "block_size": block_size,
        "client_block_limit": pool_cfg["client_block_limit"],
        "blocks_used": len(entries),
        "blocks_total": total_blocks,
        "pool_utilization_pct": round(pool_util_pct, 1),
        "total_ports_used": total_ports,
        "total_port_capacity": total_capacity,
        "port_utilization_pct": round(port_util_pct, 1),
        "unique_clients": len(client_stats),
        "avg_blocks_per_client": round(len(entries) / len(client_stats), 1) if client_stats else 0,
        "blocks": blocks,
        "clients": clients,
        "external_ip_distribution": dict(sorted(ext_ip_dist.items(), key=lambda x: x[1], reverse=True)),
    }


def json_host(host_ip: str, pba_entries: list[dict], mappings: list[dict], pools: dict) -> dict:
    """Build JSON data for a single host IP."""
    host_entries = [e for e in pba_entries if e["client_ip"] == host_ip]
    if not host_entries:
        return {"error": f"No port block allocations found for {host_ip}"}

    pool_name, pool_cfg = find_pool_for_ip(host_entries[0]["external_ip"], pools)
    if not pool_cfg:
        pool_cfg = {"block_size": 256, "client_block_limit": 1, "addresses": []}
        pool_name = "Unknown"

    block_size = pool_cfg["block_size"]
    total_blocks = calc_total_port_blocks(pool_cfg)
    blocks = [build_block_data(e, mappings, block_size) for e in
              sorted(host_entries, key=lambda e: (e["external_ip"], e["port_start"]))]

    total_ports = sum(b["ports_used"] for b in blocks)
    total_capacity = len(host_entries) * block_size
    util_pct = (total_ports / total_capacity * 100) if total_capacity > 0 else 0

    # Protocol totals
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
        "total_ports_used": total_ports,
        "total_port_capacity": total_capacity,
        "utilization_pct": round(util_pct, 1),
        "protocol_totals": dict(proto_totals),
        "external_ips": sorted(set(e["external_ip"] for e in host_entries)),
        "blocks": blocks,
    }


def json_pool(pool_name: str, pba_entries: list[dict], mappings: list[dict], pools: dict) -> dict:
    """Build JSON data for a specific pool."""
    pool_cfg = pools.get(pool_name)
    if not pool_cfg:
        return {"error": f"Pool '{pool_name}' not found", "available_pools": sorted(pools.keys())}

    pool_entries = filter_entries_by_pool(pba_entries, pool_name, pools)
    if not pool_entries:
        return {"error": f"No port block allocations found for pool {pool_name}"}

    total_blocks = calc_total_port_blocks(pool_cfg)
    result = build_pool_data(pool_name, pool_cfg, pool_entries, mappings, total_blocks)
    result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return result


def json_xlated_ip(xlated_ip: str, pba_entries: list[dict], mappings: list[dict], pools: dict) -> dict:
    """Build JSON data filtered by translated IP."""
    filtered = [e for e in pba_entries if e["external_ip"] == xlated_ip]
    if not filtered:
        return {"error": f"No port block allocations found for translated IP {xlated_ip}"}

    pool_name, pool_cfg = find_pool_for_ip(xlated_ip, pools)
    if not pool_cfg:
        pool_cfg = {"block_size": 256, "client_block_limit": 1, "addresses": []}
        pool_name = "Unknown"

    total_blocks = calc_total_port_blocks(pool_cfg)
    result = build_pool_data(pool_name, pool_cfg, filtered, mappings, total_blocks)
    result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result["filtered_by"] = xlated_ip
    return result


def json_all(pba_entries: list[dict], mappings: list[dict], pools: dict) -> dict:
    """Build JSON data for all pools."""
    pool_groups: dict[str, list[dict]] = defaultdict(list)
    for entry in pba_entries:
        found_pool, _ = find_pool_for_ip(entry["external_ip"], pools)
        pool_groups[found_pool or "Unknown"].append(entry)

    pool_data = []
    for pool_name in sorted(pool_groups.keys()):
        pool_cfg = pools.get(pool_name, {"block_size": 256, "client_block_limit": 1, "addresses": []})
        total_blocks = calc_total_port_blocks(pool_cfg)
        pool_data.append(build_pool_data(pool_name, pool_cfg, pool_groups[pool_name], mappings, total_blocks))

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pools": pool_data,
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
    parser = argparse.ArgumentParser(
        description="Query F5 BIG-IP CGNAT PBA stats"
    )
    parser.add_argument("--bigip", required=True, metavar="HOST",
                        help="BIG-IP hostname or IP address")
    parser.add_argument("--port", default="22", metavar="PORT",
                        help="SSH port (default: 22)")
    parser.add_argument("--user", metavar="USERNAME",
                        help="SSH username (prompts for password)")

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

    enhanced = args.enhanced
    use_json = args.json

    def log(msg: str):
        if not use_json:
            print(msg, file=sys.stderr)

    log("Fetching pool configurations...")
    pools = get_pool_configs()

    log("Fetching PBA entries...")
    pba_entries = get_pba_entries()

    if not pba_entries:
        if use_json:
            print(json.dumps({"error": "No PBA entries found on the BIG-IP."}))
        else:
            print("No PBA entries found on the BIG-IP.")
        sys.exit(0)

    if use_json:
        if args.summary:
            result = json_summary(pba_entries, pools)
        else:
            mappings = get_inbound_mappings()
            if args.pool:
                result = json_pool(args.pool, pba_entries, mappings, pools)
            elif args.xlated_ip:
                result = json_xlated_ip(args.xlated_ip, pba_entries, mappings, pools)
            elif args.all:
                result = json_all(pba_entries, mappings, pools)
            else:
                result = json_host(args.host_ip, pba_entries, mappings, pools)
        print(json.dumps(result, separators=(",", ":")))
    elif args.summary:
        show_summary(pba_entries, pools, enhanced=enhanced)
    else:
        log("Fetching inbound mappings (port usage)...")
        mappings = get_inbound_mappings()

        if args.pool:
            show_pool(args.pool, pba_entries, mappings, pools, enhanced=enhanced)
        elif args.xlated_ip:
            filtered = [e for e in pba_entries if e["external_ip"] == args.xlated_ip]
            if not filtered:
                print(f"No port block allocations found for translated IP {args.xlated_ip}")
            else:
                pool_name, pool_cfg = find_pool_for_ip(args.xlated_ip, pools)
                if not pool_cfg:
                    pool_cfg = {"block_size": 256, "client_block_limit": 1, "addresses": []}
                    pool_name = "Unknown"
                total_blocks = calc_total_port_blocks(pool_cfg)
                print_pool_header(pool_name, pool_cfg, len(filtered), total_blocks,
                                  enhanced=enhanced)
                print_pba_rows(filtered, mappings, pool_cfg["block_size"], enhanced=enhanced)
                if enhanced:
                    print_enhanced_pool_footer(filtered, mappings, pool_cfg, pool_name,
                                              total_blocks)
        elif args.all:
            show_all(pba_entries, mappings, pools, enhanced=enhanced)
        else:
            show_host(args.host_ip, pba_entries, mappings, pools, enhanced=enhanced)


if __name__ == "__main__":
    main()
