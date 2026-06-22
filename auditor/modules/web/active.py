"""Active web reconnaissance — requires explicit --authorized flag."""
from __future__ import annotations

import asyncio
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from auditor.utils.console import print_step, print_ok, print_warn, print_err


@dataclass
class NmapResult:
    target: str
    open_ports: list[dict] = field(default_factory=list)
    raw_output: str = ""


@dataclass
class NucleiResult:
    target: str
    findings: list[dict] = field(default_factory=list)


def run_nmap(target: str, output_dir: Path, ports: str = "80,443,8080,8443,8888,9090,3000,5000") -> NmapResult:
    """Run nmap service scan. target must be validated before calling."""
    out_prefix = output_dir / f"nmap_{target.replace('/', '_')}"
    cmd = [
        "nmap", "-sV", "-sC",
        "-p", ports,
        "--min-rate", "1000",
        "-oA", str(out_prefix),
        target,
    ]
    print_step(f"nmap: {target} ports={ports}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        raw = result.stdout
        # Basic port extraction from nmap output
        open_ports = []
        for line in raw.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    open_ports.append({
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2],
                        "version": " ".join(parts[3:]) if len(parts) > 3 else "",
                    })
        print_ok(f"nmap: {len(open_ports)} open ports on {target}")
        return NmapResult(target=target, open_ports=open_ports, raw_output=raw)
    except FileNotFoundError:
        print_warn("nmap not found — install with: brew install nmap")
        return NmapResult(target=target)
    except subprocess.TimeoutExpired:
        print_warn(f"nmap timed out on {target}")
        return NmapResult(target=target)


def run_nuclei(targets_file: Path, output_dir: Path, severity: str = "critical,high,medium") -> list[NucleiResult]:
    """Run nuclei against live hosts. targets_file = file with one URL per line."""
    out_file = output_dir / "nuclei_results.jsonl"
    cmd = [
        "nuclei",
        "-l", str(targets_file),
        "-t", "cves/",
        "-t", "exposures/",
        "-t", "misconfigurations/",
        "-severity", severity,
        "-json-export", str(out_file),
        "-silent",
    ]
    print_step(f"nuclei: scanning {targets_file} (severity={severity})")
    try:
        subprocess.run(cmd, timeout=600, capture_output=True)
    except FileNotFoundError:
        print_warn("nuclei not found — install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return []
    except subprocess.TimeoutExpired:
        print_warn("nuclei timed out")

    results: list[NucleiResult] = []
    if not out_file.exists():
        return results

    targets_map: dict[str, NucleiResult] = {}
    with open(out_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "unknown")
                if host not in targets_map:
                    targets_map[host] = NucleiResult(target=host)
                targets_map[host].findings.append(data)
            except json.JSONDecodeError:
                continue

    results = list(targets_map.values())
    total = sum(len(r.findings) for r in results)
    print_ok(f"nuclei: {total} findings across {len(results)} targets")
    return results


async def run_active_recon(
    domain: str,
    live_hosts: list[str],
    output_dir: Path,
) -> tuple[list[NmapResult], list[NucleiResult]]:
    """Run nmap + nuclei against confirmed live hosts."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write live hosts to file for nuclei
    targets_file = output_dir / "live_hosts.txt"
    targets_file.write_text("\n".join(live_hosts) + "\n")

    # nmap on domain IP
    nmap_results = []
    nmap_result = run_nmap(domain, output_dir)
    nmap_results.append(nmap_result)

    # nuclei
    nuclei_results = run_nuclei(targets_file, output_dir)

    return nmap_results, nuclei_results
