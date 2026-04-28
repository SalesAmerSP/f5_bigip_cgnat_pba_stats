#!/usr/bin/python3
"""
CGNAT PBA Stats - Runs locally on F5 BIG-IP.
Queries per-subscriber port block allocations using lsndb and tmsh.

Install:
    scp cgnat_pba_stats_bigip_compatible.py bigip:/shared/scripts/pba-stats
    ssh bigip 'chmod +x /shared/scripts/pba-stats'
    ssh bigip 'ln -sf /shared/scripts/pba-stats /usr/local/bin/pba-stats'

Usage:
    pba-stats <host_ip>
    pba-stats --pool [pool_name]
    pba-stats --xlated-ip [ip_address]
    pba-stats --all
    pba-stats --summary
    pba-stats --all --enhanced
"""

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime


def run_cmd(cmd, timeout=30):
    """Run a local command and return stdout."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Data collection (local - no SSH)
# ---------------------------------------------------------------------------

def get_pool_configs():
    raw = run_cmd("tmsh list security nat source-translation one-line")
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
            print("WARNING: Could not parse block-size/client-block-limit for %s" % name, file=sys.stderr)
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


def get_pba_entries():
    raw = run_cmd("lsndb list pba")
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


def get_inbound_mappings():
    raw = run_cmd("lsndb list inbound", timeout=60)
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
                "client_port": int(m.group(4)),
                "protocol": m.group(5),
                "age": int(m.group(6)),
            })
    return mappings


# ---------------------------------------------------------------------------
# Pool / IP helpers
# ---------------------------------------------------------------------------

def infer_block_size(entries):
    """Infer block size from PBA entries' port ranges when pool config is unavailable."""
    if entries:
        e = entries[0]
        return e["port_end"] - e["port_start"] + 1
    return 0


def unknown_pool_cfg(entries):
    """Build a placeholder pool config for entries that don't match any known pool."""
    return {"block_size": infer_block_size(entries), "client_block_limit": 0, "addresses": []}


def find_pool_for_ip(external_ip, pools):
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


def build_mapping_indexes(mappings):
    mapping_index = {}
    client_mapping_index = defaultdict(list)
    for m in mappings:
        key = (m["client_ip"], m["translation_ip"])
        mapping_index.setdefault(key, []).append(m)
        client_mapping_index[m["client_ip"]].append(m)
    return mapping_index, client_mapping_index


def count_ports_used(client_ip, translation_ip, port_start, port_end, mapping_index):
    ports = set()
    for m in mapping_index.get((client_ip, translation_ip), []):
        if port_start <= m["translation_port"] <= port_end:
            ports.add(m["translation_port"])
    return len(ports)


def count_ports_by_protocol(client_ip, translation_ip, port_start, port_end, mapping_index):
    proto_counts = defaultdict(int)
    for m in mapping_index.get((client_ip, translation_ip), []):
        if port_start <= m["translation_port"] <= port_end:
            proto_counts[m.get("protocol", "?")] += 1
    return dict(proto_counts)


def determine_block_state(ports_used, ttl):
    if ports_used > 0:
        return "Active"
    if ttl > 0:
        return "Query"
    return "Inactive"


def calc_total_port_blocks(pool_cfg):
    total_ips = 0
    for addr_str in pool_cfg.get("addresses", []):
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
    port_range = 65535 - 1024 + 1
    block_size = pool_cfg.get("block_size", 0)
    if block_size == 0:
        return 0
    blocks_per_ip = port_range // block_size
    return total_ips * blocks_per_ip


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_pool_header(pool_name, pool_cfg, used_blocks, total_blocks, per_host=False,
                      enhanced=False):
    block_size = pool_cfg["block_size"]
    max_blocks = pool_cfg["client_block_limit"]
    now = datetime.now()
    print(now.strftime("%b %d %H:%M:%S"))
    print()
    print("Pool name: %s" % pool_name)
    print("Port-overloading-factor: %5d     Port block size:  %d" % (1, block_size))
    print("Max port blocks per host: %4d     Port block active timeout:    0" % max_blocks)
    if per_host:
        print("Used/total port blocks per host: %d/%d" % (used_blocks, max_blocks))
    else:
        print("Used/total port blocks: %d/%d" % (used_blocks, total_blocks))
    if enhanced and total_blocks > 0:
        util_pct = used_blocks / total_blocks * 100
        print("Pool utilization: %.1f%%" % util_pct)
    base_hdr = "%-30s%-31s%12s%18s%17s" % ("Host_IP", "External_IP", "Port_Block", "Ports_Used/", "Block_State/")
    base_sub = "%-30s%-31s%12s%18s%17s" % ("", "", "Range", "Ports_Total", "Left_Time(s)")
    if enhanced:
        base_hdr += "  %6s  %-16s  %s" % ("Util%", "Subscriber_ID", "Protocol_Breakdown")
        base_sub += "  %6s  %-16s  %s" % ("", "", "")
    print(base_hdr)
    print(base_sub)


def print_pba_rows(entries, mapping_index, block_size, enhanced=False):
    entries.sort(key=lambda e: (e["external_ip"], e["port_start"]))
    for entry in entries:
        port_range = "%d-%d" % (entry["port_start"], entry["port_end"])
        ports_used = count_ports_used(
            entry["client_ip"], entry["external_ip"], entry["port_start"], entry["port_end"], mapping_index
        )
        state = determine_block_state(ports_used, entry["ttl"])
        ttl_str = "-" if entry["ttl"] == 0 else str(entry["ttl"])
        line = "%-30s%-31s%12s%12d/%d*1    %s/%s" % (
            entry["client_ip"], entry["external_ip"], port_range,
            ports_used, block_size, state, ttl_str
        )
        if enhanced:
            util_pct = (ports_used / block_size * 100) if block_size > 0 else 0
            proto_counts = count_ports_by_protocol(
                entry["client_ip"], entry["external_ip"], entry["port_start"], entry["port_end"], mapping_index
            )
            if proto_counts:
                proto_str = " ".join("%s:%d" % (proto, cnt) for proto, cnt in sorted(proto_counts.items()))
            else:
                proto_str = "-"
            sub_id = entry.get("subscriber_id", "-")
            line += "  %5.1f%%  %-16s  %s" % (util_pct, sub_id, proto_str)
        print(line)


def print_enhanced_host_footer(host_ip, entries, client_mapping_index, pool_cfg):
    block_size = pool_cfg["block_size"]
    max_blocks = pool_cfg["client_block_limit"]
    num_blocks = len(entries)
    total_capacity = num_blocks * block_size

    total_ports = 0
    proto_totals = defaultdict(int)
    for entry in entries:
        for m in client_mapping_index.get(host_ip, []):
            if entry["port_start"] <= m["translation_port"] <= entry["port_end"]:
                total_ports += 1
                proto_totals[m.get("protocol", "?")] += 1

    util_pct = (total_ports / total_capacity * 100) if total_capacity > 0 else 0
    blocks_remaining = max(0, max_blocks - num_blocks)

    print()
    print("  --- Enhanced Host Summary for %s ---" % host_ip)
    print("  Total ports in use:    %6d  /  %d capacity" % (total_ports, total_capacity))
    print("  Overall utilization:   %5.1f%%" % util_pct)
    print("  Blocks allocated:      %6d  /  %d max" % (num_blocks, max_blocks))
    print("  Blocks remaining:      %6d" % blocks_remaining)
    if proto_totals:
        proto_str = "  ".join("%s: %d" % (proto, cnt) for proto, cnt in sorted(proto_totals.items()))
        print("  Protocol totals:       %s" % proto_str)
    ext_ips = sorted(set(e["external_ip"] for e in entries))
    print("  External IPs:          %s" % ", ".join(ext_ips))


def print_enhanced_pool_footer(entries, client_mapping_index, pool_cfg, pool_name, total_blocks,
                               top_n=10):
    block_size = pool_cfg["block_size"]

    # Aggregate per-client stats
    client_stats = {}
    for entry in entries:
        cip = entry["client_ip"]
        if cip not in client_stats:
            client_stats[cip] = {"blocks": 0, "ports": 0, "external_ips": set()}
        client_stats[cip]["blocks"] += 1
        client_stats[cip]["external_ips"].add(entry["external_ip"])
        for m in client_mapping_index.get(cip, []):
            if entry["port_start"] <= m["translation_port"] <= entry["port_end"]:
                client_stats[cip]["ports"] += 1

    unique_clients = len(client_stats)
    total_blocks_used = len(entries)
    avg_blocks = total_blocks_used / unique_clients if unique_clients > 0 else 0
    total_ports = sum(s["ports"] for s in client_stats.values())
    # Pool port capacity is the full pool (all available blocks * block_size),
    # not just the blocks currently allocated. Previously this used
    # total_blocks_used, which understated the denominator and made the
    # utilization percentage look dramatically higher than reality.
    total_capacity = total_blocks * block_size
    util_pct = (total_ports / total_capacity * 100) if total_capacity > 0 else 0
    pool_util_pct = (total_blocks_used / total_blocks * 100) if total_blocks > 0 else 0

    print()
    print("  --- Enhanced Pool Summary: %s ---" % pool_name)
    print("  Unique clients:        %6d" % unique_clients)
    print("  Total blocks used:     %6d  /  %d total  (%.1f%%)" % (
        total_blocks_used, total_blocks, pool_util_pct))
    print("  Total ports in use:    %6d  /  %d capacity  (%.1f%%)" % (
        total_ports, total_capacity, util_pct))
    print("  Avg blocks per client: %6.1f" % avg_blocks)

    # Top N subscribers by port usage
    top_by_ports = sorted(client_stats.items(), key=lambda x: x[1]["ports"], reverse=True)[:top_n]
    print()
    print("  Top %d subscribers by port usage:" % min(top_n, len(top_by_ports)))
    print("    %-20s %8s %8s %8s  %s" % ("Client_IP", "Ports", "Blocks", "Util%", "External_IPs"))
    for cip, stats in top_by_ports:
        cap = stats["blocks"] * block_size
        u = (stats["ports"] / cap * 100) if cap > 0 else 0
        ext_str = ", ".join(sorted(stats["external_ips"]))
        print("    %-20s %8d %8d %7.1f%%  %s" % (cip, stats["ports"], stats["blocks"], u, ext_str))

    # Top N subscribers by block count
    top_by_blocks = sorted(client_stats.items(), key=lambda x: x[1]["blocks"], reverse=True)[:top_n]
    print()
    print("  Top %d subscribers by block count:" % min(top_n, len(top_by_blocks)))
    print("    %-20s %8s %8s %8s" % ("Client_IP", "Blocks", "Ports", "Util%"))
    for cip, stats in top_by_blocks:
        cap = stats["blocks"] * block_size
        u = (stats["ports"] / cap * 100) if cap > 0 else 0
        print("    %-20s %8d %8d %7.1f%%" % (cip, stats["blocks"], stats["ports"], u))

    # External IP distribution
    ext_ip_counts = defaultdict(int)
    for entry in entries:
        ext_ip_counts[entry["external_ip"]] += 1
    print()
    print("  External IP distribution (%d IPs):" % len(ext_ip_counts))
    print("    %-20s %8s %8s" % ("External_IP", "Blocks", "Alloc%"))
    for eip, cnt in sorted(ext_ip_counts.items(), key=lambda x: x[1], reverse=True):
        blocks_per_ip = (65535 - 1024 + 1) // block_size
        alloc_pct = (cnt / blocks_per_ip * 100) if blocks_per_ip > 0 else 0
        print("    %-20s %8d %7.1f%%" % (eip, cnt, alloc_pct))


def show_host(host_ip, pba_entries, mapping_index, client_mapping_index, pools, enhanced=False):
    host_entries = [e for e in pba_entries if e["client_ip"] == host_ip]
    if not host_entries:
        print("No port block allocations found for %s" % host_ip)
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


def show_pool(pool_name, pba_entries, mapping_index, client_mapping_index, pools, enhanced=False):
    pool_cfg = pools.get(pool_name)
    if not pool_cfg:
        print("Pool '%s' not found. Available pools:" % pool_name)
        for name in sorted(pools.keys()):
            print("  %s" % name)
        return
    pool_entries = []
    for entry in pba_entries:
        found_pool, _ = find_pool_for_ip(entry["external_ip"], pools)
        if found_pool == pool_name:
            pool_entries.append(entry)
    if not pool_entries:
        print("No port block allocations found for pool %s" % pool_name)
        return
    total_blocks = calc_total_port_blocks(pool_cfg)
    print_pool_header(pool_name, pool_cfg, len(pool_entries), total_blocks, enhanced=enhanced)
    print_pba_rows(pool_entries, mapping_index, pool_cfg["block_size"], enhanced=enhanced)
    if enhanced:
        print_enhanced_pool_footer(pool_entries, client_mapping_index, pool_cfg, pool_name, total_blocks)


def show_all(pba_entries, mapping_index, client_mapping_index, pools, enhanced=False):
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


def show_summary(pba_entries, pools, enhanced=False):
    blocks_used = defaultdict(int)
    client_ips = defaultdict(set)
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
        print("%-45s %8s %12s %11s %11s %9s %7s %15s" % (
            "Pool Name", "Clients", "Blocks Used", "Total Blks", "Block Size",
            "Max Blks", "Pool%", "Avg Blk/Client"))
        print("-" * 122)
    else:
        print("%-45s %8s %12s %11s %11s" % ("Pool Name", "Clients", "Blocks Used", "Block Size", "Max Blocks"))
        print("-" * 90)

    for pool_nm in sorted(blocks_used.keys()):
        num_clients = len(client_ips[pool_nm])
        num_blocks = blocks_used[pool_nm]
        pool_cfg = pools.get(pool_nm, {})
        block_size = pool_cfg.get("block_size", "?")
        max_blk = pool_cfg.get("client_block_limit", "?")
        if enhanced:
            total_blks = calc_total_port_blocks(pool_cfg) if pool_cfg.get("addresses") else 0
            pool_pct = (num_blocks / total_blks * 100) if total_blks > 0 else 0
            avg_blk = num_blocks / num_clients if num_clients > 0 else 0
            print("%-45s %8d %12d %11d %11s %9s %6.1f%% %15.1f" % (
                pool_nm, num_clients, num_blocks, total_blks, block_size,
                max_blk, pool_pct, avg_blk))
        else:
            print("%-45s %8d %12d %11s %11s" % (
                pool_nm, num_clients, num_blocks, block_size, max_blk))


# ---------------------------------------------------------------------------
# JSON output builders
# ---------------------------------------------------------------------------

def build_block_data(entry, mapping_index, block_size):
    ports_used = count_ports_used(
        entry["client_ip"], entry["external_ip"], entry["port_start"], entry["port_end"], mapping_index
    )
    proto_counts = count_ports_by_protocol(
        entry["client_ip"], entry["external_ip"], entry["port_start"], entry["port_end"], mapping_index
    )
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


def build_pool_data(pool_name, pool_cfg, entries, mapping_index, total_blocks):
    block_size = pool_cfg["block_size"]
    blocks = [build_block_data(e, mapping_index, block_size) for e in
              sorted(entries, key=lambda e: (e["external_ip"], e["port_start"]))]

    client_stats = {}
    for block in blocks:
        cip = block["client_ip"]
        if cip not in client_stats:
            client_stats[cip] = {"blocks": 0, "ports_used": 0, "external_ips": set()}
        client_stats[cip]["blocks"] += 1
        client_stats[cip]["ports_used"] += block["ports_used"]
        client_stats[cip]["external_ips"].add(block["external_ip"])

    total_ports = sum(b["ports_used"] for b in blocks)
    # Pool port capacity is the full pool (all available blocks * block_size),
    # not just the blocks currently allocated.
    total_capacity = total_blocks * block_size
    pool_util_pct = (len(entries) / total_blocks * 100) if total_blocks > 0 else 0
    port_util_pct = (total_ports / total_capacity * 100) if total_capacity > 0 else 0

    ext_ip_dist = defaultdict(int)
    for e in entries:
        ext_ip_dist[e["external_ip"]] += 1

    clients = []
    for cip in sorted(client_stats):
        stats = client_stats[cip]
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


def json_host(host_ip, pba_entries, mapping_index, pools):
    host_entries = [e for e in pba_entries if e["client_ip"] == host_ip]
    if not host_entries:
        return {"error": "No port block allocations found for %s" % host_ip}

    pool_name, pool_cfg = find_pool_for_ip(host_entries[0]["external_ip"], pools)
    if not pool_cfg:
        pool_cfg = unknown_pool_cfg(host_entries)
        pool_name = "Unknown"

    block_size = pool_cfg["block_size"]
    blocks = [build_block_data(e, mapping_index, block_size) for e in
              sorted(host_entries, key=lambda e: (e["external_ip"], e["port_start"]))]

    total_ports = sum(b["ports_used"] for b in blocks)
    total_capacity = len(host_entries) * block_size
    util_pct = (total_ports / total_capacity * 100) if total_capacity > 0 else 0

    proto_totals = defaultdict(int)
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


def json_pool(pool_name, pba_entries, mapping_index, pools):
    pool_cfg = pools.get(pool_name)
    if not pool_cfg:
        return {"error": "Pool '%s' not found" % pool_name, "available_pools": sorted(pools.keys())}

    pool_entries = []
    for entry in pba_entries:
        found_pool, _ = find_pool_for_ip(entry["external_ip"], pools)
        if found_pool == pool_name:
            pool_entries.append(entry)
    if not pool_entries:
        return {"error": "No port block allocations found for pool %s" % pool_name}

    total_blocks = calc_total_port_blocks(pool_cfg)
    result = build_pool_data(pool_name, pool_cfg, pool_entries, mapping_index, total_blocks)
    result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return result


def json_xlated_ip(xlated_ip, pba_entries, mapping_index, pools):
    filtered = [e for e in pba_entries if e["external_ip"] == xlated_ip]
    if not filtered:
        return {"error": "No port block allocations found for translated IP %s" % xlated_ip}

    pool_name, pool_cfg = find_pool_for_ip(xlated_ip, pools)
    if not pool_cfg:
        pool_cfg = unknown_pool_cfg(filtered)
        pool_name = "Unknown"

    total_blocks = calc_total_port_blocks(pool_cfg)
    result = build_pool_data(pool_name, pool_cfg, filtered, mapping_index, total_blocks)
    result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result["filtered_by"] = xlated_ip
    return result


def json_all(pba_entries, mapping_index, pools):
    pool_groups = defaultdict(list)
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


def json_summary(pba_entries, pools):
    blocks_used_map = defaultdict(int)
    client_ips_map = defaultdict(set)

    for entry in pba_entries:
        pool_name, _ = find_pool_for_ip(entry["external_ip"], pools)
        if not pool_name:
            pool_name = "Unknown"
        blocks_used_map[pool_name] += 1
        client_ips_map[pool_name].add(entry["client_ip"])

    pool_summaries = []
    for pname in sorted(blocks_used_map.keys()):
        num_clients = len(client_ips_map[pname])
        num_blocks = blocks_used_map[pname]
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="CGNAT PBA Stats")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("host_ip", nargs="?", help="Client/subscriber IP")
    group.add_argument("--pool", metavar="POOL_NAME", help="Show port blocks for a pool")
    group.add_argument("--xlated-ip", metavar="IP", help="Filter by translated IP")
    group.add_argument("--all", action="store_true", help="Show all port blocks")
    group.add_argument("--summary", action="store_true", help="PBA usage summary")

    parser.add_argument("--enhanced", action="store_true",
                        help="Show enhanced stats (utilization %%, protocol breakdown, top subscribers, etc.)")
    parser.add_argument("--json", action="store_true",
                        help="Output data as JSON instead of text")

    args = parser.parse_args()

    pools = get_pool_configs()
    pba_entries = get_pba_entries()

    if not pba_entries:
        print("No PBA entries found.")
        sys.exit(0)

    enhanced = args.enhanced
    use_json = args.json

    if use_json:
        if args.summary:
            result = json_summary(pba_entries, pools)
        else:
            mappings = get_inbound_mappings()
            mapping_index, client_mapping_index = build_mapping_indexes(mappings)
            if args.pool:
                result = json_pool(args.pool, pba_entries, mapping_index, pools)
            elif args.xlated_ip:
                result = json_xlated_ip(args.xlated_ip, pba_entries, mapping_index, pools)
            elif args.all:
                result = json_all(pba_entries, mapping_index, pools)
            else:
                result = json_host(args.host_ip, pba_entries, mapping_index, pools)
        print(json.dumps(result, separators=(",", ":")))
    elif args.summary:
        show_summary(pba_entries, pools, enhanced=enhanced)
    else:
        mappings = get_inbound_mappings()
        mapping_index, client_mapping_index = build_mapping_indexes(mappings)

        if args.pool:
            show_pool(args.pool, pba_entries, mapping_index, client_mapping_index, pools, enhanced=enhanced)
        elif args.xlated_ip:
            filtered = [e for e in pba_entries if e["external_ip"] == args.xlated_ip]
            if not filtered:
                print("No port block allocations found for translated IP %s" % args.xlated_ip)
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


if __name__ == "__main__":
    main()
