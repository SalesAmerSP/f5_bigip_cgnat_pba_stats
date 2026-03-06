# CGNAT PBA Monitoring

Tools for monitoring CGNAT Port Block Allocation (PBA) on F5 BIG-IP.

## Components

### [python/](python/)

Python scripts for querying and collecting PBA statistics from F5 BIG-IP CGNAT devices.

- **cgnat_pba_stats.py** - Interactive query tool (runs remotely via SSH)
- **cgnat_pba_stats_bigip_compatible.py** - Interactive query tool (runs locally on the BIG-IP)
- **cgnat_pba_collect.py** - Data collector that exports per-subscriber stats to CSV or MySQL

See [python/README.md](python/README.md) for detailed usage.

### [python/install-pba-stats.sh](python/install-pba-stats.sh)

Bash installer that deploys `cgnat_pba_stats_bigip_compatible.py` to a BIG-IP. Validates the target is a BIG-IP before installing, copies the script to persistent storage, adds it to PATH, and configures boot persistence.

```bash
./python/install-pba-stats.sh <bigip_host> [--user USERNAME] [--password] [--port PORT]
```

## Compatibility

These tools were developed and tested against **TMOS 17.1** and **17.5.1.3 (build 0.0.19)**. Older TMOS versions may not be supported, as differences in `lsndb` or `tmsh` command output formats could cause parsing failures.

## Background

F5 BIG-IP CGNAT uses PBA to allocate port blocks to subscribers. BIG-IP does not provide a single CLI command to view per-subscriber port block allocations in a consolidated format. These tools bridge that gap by querying `lsndb` (for live PBA/inbound state) and `tmsh` (for pool configuration), then presenting the data in a readable format.

## Data Sources

| Command | Purpose |
|---------|---------|
| `lsndb list pba` | Port block allocations (client IP, external IP, port range, TTL) |
| `lsndb list inbound` | Active inbound mappings (used to count ports in use per block) |
| `tmsh list security nat source-translation one-line` | Pool configuration (block size, client block limit, address ranges) |
