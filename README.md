# pc-audit

Engineer-grade Windows PC audit tool that generates **JSON + Markdown** system reports with a single click.

---

## Features

- One-click execution on Windows (`pc_audit.bat`)
- Crash-proof, best-effort data collection (partial output even if some probes fail)
- Dual output:
  - **JSON** for machines / automation / diff
  - **Markdown** for humans
- Accurate GPU detection:
  - NVIDIA: authoritative VRAM & driver via `nvidia-smi`
  - Others: Win32 fallback
- AI environment sanity checks:
  - PyTorch version
  - CUDA availability & device name
- Hardware & OS coverage:
  - CPU / RAM (per-module) / Motherboard / BIOS
  - Storage (physical disks + volumes)
  - Network adapters
  - Power plan & sleep states
  - Startup items
  - Monitor EDID (best-effort)

---

## Output

Each run generates two timestamped files:

```
pc_audit_report_YYYYMMDD_HHMMSS.json
pc_audit_report_YYYYMMDD_HHMMSS.md
```

Files are saved to the Desktop by default.

---

## Quick Start (One Click)

1. Install **Python 3.10+** on Windows  
   - During installation, enable **Add Python to PATH**
2. Clone this repository
3. Double-click:
   ```
   pc_audit.bat
   ```

No PowerShell commands required.

---

## Requirements

### Required

- Windows 10 / Windows 11
- Python 3.10+ (recommended: 3.11+)

### Optional (Recommended for full details)

Install these packages to get richer hardware and runtime details:

```
pip install psutil wmi
```

### Optional (AI / CUDA checks)

To include PyTorch and CUDA availability in the report:

```
pip install torch
```

### Optional (NVIDIA GPU accuracy)

Accurate NVIDIA GPU VRAM and driver information relies on `nvidia-smi`, which is available after installing the NVIDIA driver.

The tool runs without optional dependencies and will gracefully degrade when certain components are unavailable.

---

## Security & Privacy

- IP addresses, MAC addresses, and live connections are **redacted by default**
- Do **not** commit real audit reports to public repositories
- Use sanitized examples if sharing reports

---

## Known Limitations

- PSU model/wattage cannot be reliably detected via OS APIs
- `Get-PhysicalDisk` may be unavailable on some storage controllers
- Monitor EDID information may be missing when using docks/adapters
- Some `powercfg` queries require Administrator privileges
- Corporate-managed devices may restrict WMI or PowerShell access

---

## Roadmap

- Diff report (`diff.md`) generation between two audits
- PDF export
- Portable `.exe` build

---

## License

MIT License
