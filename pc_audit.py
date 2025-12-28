# pc_audit.py
# Windows 10/11 system audit -> JSON + Markdown (timestamped filenames)
# Usage: python .\pc_audit.py
#
# Outputs (Desktop by default):
#   pc_audit_report_YYYYMMDD_HHMMSS.json
#   pc_audit_report_YYYYMMDD_HHMMSS.md

import os
import json
import socket
import platform
import subprocess
import traceback
from datetime import datetime

# Optional deps
try:
    import psutil  # pip install psutil
except Exception:
    psutil = None

try:
    import wmi  # pip install WMI
except Exception:
    wmi = None

ERRORS = []


# -----------------------------
# Utilities
# -----------------------------
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ts_compact():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def desktop_path():
    p = os.path.join(os.path.expanduser("~"), "Desktop")
    return p if os.path.isdir(p) else os.getcwd()


def log_error(stage, err, detail=None):
    item = {"time": now_str(), "stage": stage, "error": str(err)}
    if detail:
        item["detail"] = detail
    ERRORS.append(item)
    print(f"[ERROR] {stage}: {err}")
    if detail:
        print(detail[:2000] + ("\n... (truncated)" if len(detail) > 2000 else ""))


def safe_call(stage, fn, default):
    try:
        return fn()
    except Exception as e:
        log_error(stage, e, traceback.format_exc())
        return default


def run_cmd(cmd, timeout=25):
    """
    Run a command and return dict result (never throws).
    Force UTF-8 decoding and replace undecodable bytes to avoid cp950 UnicodeDecodeError.
    """
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=isinstance(cmd, str),
        )
        return {
            "ok": p.returncode == 0,
            "stdout": (p.stdout or "").strip(),
            "stderr": (p.stderr or "").strip(),
            "returncode": p.returncode,
            "cmd": cmd if isinstance(cmd, str) else " ".join(cmd),
        }
    except Exception as e:
        return {
            "ok": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "cmd": cmd if isinstance(cmd, str) else " ".join(cmd),
        }


def run_powershell(ps_script, timeout=25):
    # Force UTF-8 output in PowerShell to reduce encoding ambiguity
    wrapped = (
        "$OutputEncoding = [Console]::OutputEncoding = "
        "[System.Text.UTF8Encoding]::new(); "
        + ps_script
    )
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", wrapped]
    return run_cmd(cmd, timeout=timeout)



def safe_int(x):
    try:
        return int(x)
    except Exception:
        return None


def bytes_to_gb(b):
    try:
        return round(b / (1024 ** 3), 2)
    except Exception:
        return None


def redact_sensitive(report, redact_ip=True, redact_mac=True, redact_connections=True):
    net = report.get("network", {})
    if redact_ip and "local_ips" in net:
        net["local_ips"] = ["[REDACTED]"] * len(net.get("local_ips", []))
    if redact_mac and "mac_addresses" in net:
        net["mac_addresses"] = ["[REDACTED]"] * len(net.get("mac_addresses", []))
    if redact_connections and "active_connections" in net:
        net["active_connections"] = {"note": "redacted"}
    report["network"] = net
    report["redaction"] = {
        "redact_ip": redact_ip,
        "redact_mac": redact_mac,
        "redact_connections": redact_connections,
    }
    return report


# -----------------------------
# Collectors (existing structure)
# -----------------------------
def get_system_identity():
    si = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "architecture": platform.architecture()[0],
        "python_version": platform.python_version(),
        "timestamp": now_str(),
    }

    ps = (
        r"$os = Get-ComputerInfo; "
        r"$o = [ordered]@{WindowsProductName=$os.WindowsProductName; WindowsVersion=$os.WindowsVersion; "
        r"OsBuildNumber=$os.OsBuildNumber; CsSystemType=$os.CsSystemType; BiosFirmwareType=$os.BiosFirmwareType}; "
        r"$o | ConvertTo-Json -Compress"
    )
    r = run_powershell(ps, timeout=25)
    if r["ok"] and r["stdout"].startswith("{"):
        try:
            si["windows"] = json.loads(r["stdout"])
        except Exception as e:
            log_error("system_identity.parse_windows_json", e, r["stdout"])
            si["windows_raw"] = r["stdout"]
    else:
        si["windows_error"] = r["stderr"] or r["stdout"]

    return si


def get_cpu_memory_wmi():
    if not wmi:
        return {"error": "WMI module not installed (pip install WMI)"}

    data = {}
    c = wmi.WMI()

    cpus = c.Win32_Processor()
    if cpus:
        cpu = cpus[0]
        data["cpu"] = {
            "name": getattr(cpu, "Name", None),
            "manufacturer": getattr(cpu, "Manufacturer", None),
            "cores_physical": getattr(cpu, "NumberOfCores", None),
            "cores_logical": getattr(cpu, "NumberOfLogicalProcessors", None),
            "max_clock_mhz": getattr(cpu, "MaxClockSpeed", None),
            "current_clock_mhz": getattr(cpu, "CurrentClockSpeed", None),
            "processor_id": getattr(cpu, "ProcessorId", None),
        }

    boards = c.Win32_BaseBoard()
    if boards:
        b = boards[0]
        data["motherboard"] = {
            "manufacturer": getattr(b, "Manufacturer", None),
            "product": getattr(b, "Product", None),
            "serial_number": getattr(b, "SerialNumber", None),
            "version": getattr(b, "Version", None),
        }

    bios = c.Win32_BIOS()
    if bios:
        b = bios[0]
        data["bios"] = {
            "manufacturer": getattr(b, "Manufacturer", None),
            "version": getattr(b, "SMBIOSBIOSVersion", None),
            "release_date": str(getattr(b, "ReleaseDate", ""))[:8],
            "serial_number": getattr(b, "SerialNumber", None),
        }

    mems = c.Win32_PhysicalMemory()
    modules = []
    total = 0
    for m in mems:
        cap = safe_int(getattr(m, "Capacity", 0) or 0) or 0
        total += cap
        modules.append({
            "bank_label": getattr(m, "BankLabel", None),
            "device_locator": getattr(m, "DeviceLocator", None),
            "manufacturer": getattr(m, "Manufacturer", None),
            "part_number": (getattr(m, "PartNumber", None) or "").strip() if hasattr(m, "PartNumber") else None,
            "serial_number": getattr(m, "SerialNumber", None),
            "capacity_gb": bytes_to_gb(cap),
            "speed_mhz": getattr(m, "Speed", None),
            "configured_clock_mhz": getattr(m, "ConfiguredClockSpeed", None),
        })
    data["memory"] = {"total_gb": bytes_to_gb(total), "modules": modules}

    arrays = c.Win32_PhysicalMemoryArray()
    if arrays:
        data["memory"]["slots"] = getattr(arrays[0], "MemoryDevices", None)

    return data


def get_gpu():
    gpu = {"via": {}}

    r = run_cmd(
        ["nvidia-smi", "--query-gpu=name,driver_version,memory.total,memory.free,pci.bus_id", "--format=csv,noheader,nounits"],
        timeout=10,
    )
    if r["ok"] and r["stdout"]:
        gpus = []
        for line in r["stdout"].splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                gpus.append({
                    "name": parts[0],
                    "driver_version": parts[1],
                    "vram_total_mb": safe_int(parts[2]),
                    "vram_free_mb": safe_int(parts[3]),
                    "pci_bus_id": parts[4],
                })
        gpu["via"]["nvidia_smi"] = {"available": True, "gpus": gpus}
    else:
        gpu["via"]["nvidia_smi"] = {"available": False, "error": r["stderr"] or r["stdout"]}

    ps = (
        r"Get-CimInstance Win32_VideoController | "
        r"Select-Object Name,DriverVersion,VideoProcessor,AdapterRAM,CurrentHorizontalResolution,CurrentVerticalResolution,PNPDeviceID | "
        r"ConvertTo-Json -Compress"
    )
    r = run_powershell(ps, timeout=25)
    if r["ok"] and r["stdout"]:
        try:
            obj = json.loads(r["stdout"])
            if isinstance(obj, dict):
                obj = [obj]
            for o in obj:
                if "AdapterRAM" in o and o["AdapterRAM"] is not None:
                    try:
                        o["AdapterRAM_GB_estimate"] = round(int(o["AdapterRAM"]) / (1024**3), 2)
                    except Exception:
                        pass
            gpu["via"]["win32_videocontroller"] = obj
        except Exception as e:
            log_error("gpu.parse_win32_videocontroller_json", e, r["stdout"])
            gpu["via"]["win32_videocontroller_raw"] = r["stdout"]
    else:
        gpu["via"]["win32_videocontroller_error"] = r["stderr"] or r["stdout"]

    return gpu


def get_storage():
    st = {"physical_disks": [], "logical_volumes": []}

    ps = (
        r"Get-PhysicalDisk | "
        r"Select-Object FriendlyName,MediaType,BusType,Size,SerialNumber,HealthStatus,OperationalStatus | "
        r"ConvertTo-Json -Compress"
    )
    r = run_powershell(ps, timeout=25)
    if r["ok"] and r["stdout"]:
        try:
            obj = json.loads(r["stdout"])
            if isinstance(obj, dict):
                obj = [obj]
            for d in obj:
                size = d.get("Size")
                if size is not None:
                    try:
                        d["Size_GB"] = round(int(size) / (1024**3), 2)
                    except Exception:
                        pass
            st["physical_disks"] = obj
        except Exception as e:
            log_error("storage.parse_physicaldisk_json", e, r["stdout"])
            st["physical_disks_raw"] = r["stdout"]
    else:
        st["physical_disks_error"] = r["stderr"] or r["stdout"]

    if psutil:
        for p in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(p.mountpoint)
                st["logical_volumes"].append({
                    "device": p.device,
                    "mountpoint": p.mountpoint,
                    "fstype": p.fstype,
                    "total_gb": bytes_to_gb(usage.total),
                    "used_gb": bytes_to_gb(usage.used),
                    "free_gb": bytes_to_gb(usage.free),
                    "usage_percent": usage.percent,
                })
            except Exception:
                continue
    else:
        st["logical_volumes_error"] = "psutil not installed"

    return st


def get_network():
    net = {"adapters": [], "local_ips": [], "mac_addresses": []}

    ps = r"Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress,DriverInformation | ConvertTo-Json -Compress"
    r = run_powershell(ps, timeout=25)
    if r["ok"] and r["stdout"]:
        try:
            obj = json.loads(r["stdout"])
            if isinstance(obj, dict):
                obj = [obj]
            net["adapters"] = obj
            for a in obj:
                mac = a.get("MacAddress")
                if mac:
                    net["mac_addresses"].append(mac)
        except Exception as e:
            log_error("network.parse_getnetadapter_json", e, r["stdout"])
            net["adapters_raw"] = r["stdout"]
    else:
        net["adapters_error"] = r["stderr"] or r["stdout"]

    try:
        hostname = socket.gethostname()
        net["local_ips"] = list({ip for ip in socket.gethostbyname_ex(hostname)[2]})
    except Exception as e:
        log_error("network.local_ips", e, traceback.format_exc())

    if psutil:
        try:
            conns = psutil.net_connections(kind="inet")
            net["active_connections"] = {"count": len(conns)}
        except Exception as e:
            log_error("network.net_connections", e, traceback.format_exc())
            net["active_connections_error"] = str(e)

    return net


def get_runtime_snapshot():
    if not psutil:
        return {"error": "psutil not installed (pip install psutil)"}

    snap = {}
    snap["cpu_percent"] = psutil.cpu_percent(interval=1.0)
    vm = psutil.virtual_memory()
    snap["memory"] = {
        "total_gb": bytes_to_gb(vm.total),
        "used_gb": bytes_to_gb(vm.used),
        "free_gb": bytes_to_gb(vm.available),
        "percent": vm.percent,
    }
    return snap


def get_ai_env():
    env = {"pip_freeze": [], "pytorch": {}}

    r = run_cmd([os.sys.executable, "-m", "pip", "freeze"], timeout=25)
    if r["ok"] and r["stdout"]:
        env["pip_freeze"] = r["stdout"].splitlines()
    else:
        env["pip_freeze_error"] = r["stderr"] or r["stdout"]

    try:
        import torch  # noqa
        env["pytorch"]["torch_version"] = torch.__version__
        env["pytorch"]["cuda_available"] = bool(torch.cuda.is_available())
        env["pytorch"]["compile_cuda_version"] = getattr(torch.version, "cuda", None)
        if torch.cuda.is_available():
            env["pytorch"]["cuda_device_count"] = torch.cuda.device_count()
            env["pytorch"]["cuda_device_name_0"] = torch.cuda.get_device_name(0)
    except Exception as e:
        env["pytorch_error"] = str(e)

    return env


# -----------------------------
# New: Display / Power / Startup (incremental additions)
# -----------------------------
def get_display():
    """
    Best-effort monitor info:
    - Current resolution/refresh via WMI (VideoController) already captured in get_gpu()
    - EDID-based monitor model via WMI (WmiMonitorID)
    """
    info = {"monitors": []}

    if not wmi:
        info["error"] = "WMI not available"
        return info

    try:
        c = wmi.WMI(namespace="root\\wmi")
        mons = c.WmiMonitorID()
        for m in mons:
            # These are arrays of ushort; convert to string
            def decode(arr):
                try:
                    return "".join([chr(x) for x in arr if x != 0]).strip()
                except Exception:
                    return None

            info["monitors"].append({
                "manufacturer": decode(getattr(m, "ManufacturerName", []) or []),
                "product_code": decode(getattr(m, "ProductCodeID", []) or []),
                "serial_number": decode(getattr(m, "SerialNumberID", []) or []),
                "user_friendly_name": decode(getattr(m, "UserFriendlyName", []) or []),
                "week_of_manufacture": getattr(m, "WeekOfManufacture", None),
                "year_of_manufacture": getattr(m, "YearOfManufacture", None),
            })
    except Exception as e:
        log_error("display.WmiMonitorID", e, traceback.format_exc())
        info["error"] = str(e)

    return info


def get_power():
    """
    Power plan + sleep/hibernate settings (best-effort)
    """
    out = {"active_plan": None, "all_plans": [], "sleep": {}}

    # powercfg /getactivescheme
    r = run_cmd(["powercfg", "/getactivescheme"], timeout=10)
    if r["ok"] and r["stdout"]:
        out["active_plan_raw"] = r["stdout"]
    else:
        out["active_plan_error"] = r["stderr"] or r["stdout"]

    # powercfg /list
    r = run_cmd(["powercfg", "/list"], timeout=10)
    if r["ok"] and r["stdout"]:
        out["all_plans_raw"] = r["stdout"]
    else:
        out["all_plans_error"] = r["stderr"] or r["stdout"]

    # Sleep states
    r = run_cmd(["powercfg", "/a"], timeout=10)
    if r["ok"] and r["stdout"]:
        out["sleep"]["available_states_raw"] = r["stdout"]
    else:
        out["sleep"]["available_states_error"] = r["stderr"] or r["stdout"]

    # Hibernate enabled?
    r = run_cmd(["powercfg", "/hibernate", "query"], timeout=10)
    if r["ok"] and r["stdout"]:
        out["sleep"]["hibernate_query_raw"] = r["stdout"]
    else:
        # Not always supported; ignore noise
        out["sleep"]["hibernate_query_error"] = r["stderr"] or r["stdout"]

    return out


def get_startup_items(limit=60):
    """
    Startup items (best-effort) via WMI Win32_StartupCommand
    """
    res = {"items": [], "note": f"capped to first {limit}"}
    if not wmi:
        res["error"] = "WMI not available"
        return res

    try:
        c = wmi.WMI()
        items = c.Win32_StartupCommand()
        for it in items[:limit]:
            res["items"].append({
                "name": getattr(it, "Name", None),
                "command": getattr(it, "Command", None),
                "location": getattr(it, "Location", None),
                "user": getattr(it, "User", None),
            })
    except Exception as e:
        log_error("startup.Win32_StartupCommand", e, traceback.format_exc())
        res["error"] = str(e)

    return res


# -----------------------------
# Writers
# -----------------------------
def write_json(path, report):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def md_escape(s):
    if s is None:
        return "N/A"
    s = str(s)
    return s.replace("\n", " ").replace("\r", " ").strip()


def render_markdown(report):
    meta = report.get("meta", {})
    sysi = report.get("system_identity", {})
    hw = report.get("hardware", {})
    cpu_mb = hw.get("cpu_mem_board_bios", {})
    gpu = hw.get("gpu", {})
    storage = hw.get("storage", {})
    net = report.get("network", {})
    rt = report.get("runtime_snapshot", {})
    ai = report.get("ai_environment", {})
    disp = report.get("display", {})
    power = report.get("power", {})
    startup = report.get("startup", {})
    errors = meta.get("errors", [])

    lines = []
    lines.append("# 🖥️ PC Audit Report")
    lines.append(f"> 建檔時間: {md_escape(meta.get('report_timestamp'))}")
    lines.append("")

    # System
    lines.append("## 1) 系統身分")
    lines.append(f"- **HostName**: `{md_escape(sysi.get('hostname'))}`")
    w = sysi.get("windows", {})
    if isinstance(w, dict) and w:
        lines.append(f"- **Windows**: {md_escape(w.get('WindowsProductName'))} / Build {md_escape(w.get('OsBuildNumber'))}")
        lines.append(f"- **FirmwareType**: {md_escape(w.get('BiosFirmwareType'))}")
    else:
        lines.append(f"- **Windows**: {md_escape(sysi.get('system'))} {md_escape(sysi.get('release'))} ({md_escape(sysi.get('version'))})")
    lines.append(f"- **Machine**: {md_escape(sysi.get('machine'))} / {md_escape(sysi.get('architecture'))}")
    lines.append(f"- **Python**: {md_escape(sysi.get('python_version'))}")
    lines.append("")

    # CPU/MB/BIOS/RAM
    lines.append("## 2) 核心硬體 (CPU / 主機板 / BIOS / RAM)")
    cpu = cpu_mb.get("cpu", {})
    mb = cpu_mb.get("motherboard", {})
    bios = cpu_mb.get("bios", {})
    mem = cpu_mb.get("memory", {})
    lines.append(f"- **CPU**: {md_escape(cpu.get('name'))} ({md_escape(cpu.get('cores_physical'))}C/{md_escape(cpu.get('cores_logical'))}T)")
    lines.append(f"- **Motherboard**: {md_escape(mb.get('manufacturer'))} {md_escape(mb.get('product'))}")
    lines.append(f"- **BIOS**: {md_escape(bios.get('manufacturer'))} {md_escape(bios.get('version'))} (Release: {md_escape(bios.get('release_date'))})")
    lines.append(f"- **RAM Total**: {md_escape(mem.get('total_gb'))} GB | **Slots**: {md_escape(mem.get('slots'))}")
    mods = mem.get("modules", []) if isinstance(mem, dict) else []
    if mods:
        lines.append("  - **RAM Modules**:")
        for i, m in enumerate(mods, 1):
            lines.append(
                f"    - Slot {i}: {md_escape(m.get('manufacturer'))} "
                f"{md_escape(m.get('capacity_gb'))} GB @ {md_escape(m.get('speed_mhz'))} MHz "
                f"(Locator: {md_escape(m.get('device_locator'))})"
            )
    lines.append("")

    # GPU
    lines.append("## 3) 顯示卡 (GPU)")
    via = gpu.get("via", {}) if isinstance(gpu, dict) else {}
    ns = via.get("nvidia_smi", {})
    if isinstance(ns, dict) and ns.get("available"):
        gpus = ns.get("gpus", [])
        for g in gpus:
            lines.append(
                f"- **NVIDIA (nvidia-smi)**: {md_escape(g.get('name'))} | "
                f"VRAM {md_escape(g.get('vram_total_mb'))} MB | "
                f"Driver {md_escape(g.get('driver_version'))} | PCI {md_escape(g.get('pci_bus_id'))}"
            )
    else:
        lines.append(f"- NVIDIA nvidia-smi: {md_escape(ns.get('error'))}")

    w32 = via.get("win32_videocontroller", [])
    if isinstance(w32, list) and w32:
        lines.append("  - **Win32_VideoController (備援/可能不準)**:")
        for g in w32:
            lines.append(
                f"    - {md_escape(g.get('Name'))} | Driver {md_escape(g.get('DriverVersion'))} | "
                f"AdapterRAM_GB_est {md_escape(g.get('AdapterRAM_GB_estimate'))} | "
                f"{md_escape(g.get('CurrentHorizontalResolution'))}x{md_escape(g.get('CurrentVerticalResolution'))}"
            )
    lines.append("")

    # Display
    lines.append("## 4) 顯示器 (Monitor / Display)")
    mons = disp.get("monitors", [])
    if isinstance(mons, list) and mons:
        for i, m in enumerate(mons, 1):
            lines.append(
                f"- Monitor {i}: {md_escape(m.get('user_friendly_name'))} | "
                f"Manufacturer {md_escape(m.get('manufacturer'))} | "
                f"Serial {md_escape(m.get('serial_number'))} | "
                f"{md_escape(m.get('year_of_manufacture'))}"
            )
    else:
        lines.append(f"- 無法取得 EDID 螢幕資訊: {md_escape(disp.get('error'))}")
    lines.append("")

    # Storage
    lines.append("## 5) 儲存裝置 (Storage)")
    pds = storage.get("physical_disks", [])
    if isinstance(pds, list) and pds:
        for d in pds:
            lines.append(
                f"- Disk: {md_escape(d.get('FriendlyName'))} | {md_escape(d.get('MediaType'))} | "
                f"{md_escape(d.get('Size_GB'))} GB | Bus {md_escape(d.get('BusType'))} | Health {md_escape(d.get('HealthStatus'))}"
            )
    lvs = storage.get("logical_volumes", [])
    if isinstance(lvs, list) and lvs:
        lines.append("  - **Volumes**:")
        for v in lvs:
            lines.append(
                f"    - {md_escape(v.get('mountpoint'))}: {md_escape(v.get('used_gb'))}/{md_escape(v.get('total_gb'))} GB "
                f"({md_escape(v.get('usage_percent'))}%)"
            )
    lines.append("")

    # Network
    lines.append("## 6) 網路 (Network)")
    ad = net.get("adapters", [])
    if isinstance(ad, list) and ad:
        for a in ad:
            lines.append(
                f"- {md_escape(a.get('Name'))}: {md_escape(a.get('InterfaceDescription'))} | "
                f"{md_escape(a.get('Status'))} | {md_escape(a.get('LinkSpeed'))}"
            )
    lines.append(f"- Local IPs: {md_escape(net.get('local_ips'))}")
    lines.append("")

    # Runtime
    lines.append("## 7) 即時狀態 (Runtime Snapshot)")
    lines.append(f"- CPU: {md_escape(rt.get('cpu_percent'))}%")
    memr = rt.get("memory", {})
    if isinstance(memr, dict):
        lines.append(f"- RAM: {md_escape(memr.get('used_gb'))} / {md_escape(memr.get('total_gb'))} GB ({md_escape(memr.get('percent'))}%)")
    lines.append("")

    # Power
    lines.append("## 8) 電源與睡眠設定 (Power)")
    lines.append(f"- Active Plan: {md_escape(power.get('active_plan_raw'))}")
    lines.append(f"- Plans: {md_escape(power.get('all_plans_raw'))}")
    sleep = power.get("sleep", {})
    if isinstance(sleep, dict):
        lines.append(f"- Sleep States: {md_escape(sleep.get('available_states_raw'))}")
    lines.append("")

    # Startup
    lines.append("## 9) 啟動項目 (Startup Items)")
    items = startup.get("items", [])
    if isinstance(items, list) and items:
        for it in items:
            lines.append(
                f"- {md_escape(it.get('name'))} | {md_escape(it.get('location'))} | {md_escape(it.get('command'))}"
            )
    else:
        lines.append(f"- 無法取得啟動項目: {md_escape(startup.get('error'))}")
    lines.append("")

    # AI env
    lines.append("## 10) AI / Python 環境")
    pt = ai.get("pytorch", {})
    if isinstance(pt, dict) and pt:
        lines.append(f"- torch: {md_escape(pt.get('torch_version'))} | cuda_available={md_escape(pt.get('cuda_available'))} | compile_cuda={md_escape(pt.get('compile_cuda_version'))}")
        if pt.get("cuda_available"):
            lines.append(f"- cuda_device_0: {md_escape(pt.get('cuda_device_name_0'))}")
    else:
        lines.append(f"- PyTorch: {md_escape(ai.get('pytorch_error'))}")
    lines.append("")

    # Errors
    lines.append("## 11) 錯誤紀錄 (Errors)")
    if errors:
        for e in errors:
            lines.append(f"- [{md_escape(e.get('time'))}] {md_escape(e.get('stage'))}: {md_escape(e.get('error'))}")
    else:
        lines.append("- 無")
    lines.append("")

    return "\n".join(lines)


# -----------------------------
# Report builder (keep structure; add new sections)
# -----------------------------
def build_report(redact=True):
    report = {
        "meta": {
            "report_timestamp": now_str(),
            "tool": "pc_audit.py",
            "errors": [],
        },
        "limits": {
            "cannot_reliably_get": [
                "PSU model/wattage",
                "exact GPU power connectors",
                "case airflow / fan layout",
                "RAM dual-channel mode (reliably)",
                "PCIe lane wiring details (reliably)",
            ]
        },
        "system_identity": safe_call("system_identity", get_system_identity, {}),
        "hardware": {
            "cpu_mem_board_bios": safe_call("hardware.cpu_mem_board_bios", get_cpu_memory_wmi, {"error": "unavailable"}),
            "gpu": safe_call("hardware.gpu", get_gpu, {"error": "unavailable"}),
            "storage": safe_call("hardware.storage", get_storage, {"error": "unavailable"}),
        },
        "network": safe_call("network", get_network, {"error": "unavailable"}),
        "runtime_snapshot": safe_call("runtime_snapshot", get_runtime_snapshot, {"error": "unavailable"}),
        "ai_environment": safe_call("ai_environment", get_ai_env, {"error": "unavailable"}),

        # New sections (incremental additions)
        "display": safe_call("display", get_display, {"error": "unavailable"}),
        "power": safe_call("power", get_power, {"error": "unavailable"}),
        "startup": safe_call("startup", lambda: get_startup_items(limit=60), {"error": "unavailable"}),
    }

    if redact:
        report = redact_sensitive(report, redact_ip=True, redact_mac=True, redact_connections=True)

    report["meta"]["errors"] = ERRORS
    return report


if __name__ == "__main__":
    print("[pc_audit] Collecting system report...")

    out_dir = desktop_path()
    stamp = ts_compact()

    json_path = os.path.join(out_dir, f"pc_audit_report_{stamp}.json")
    md_path = os.path.join(out_dir, f"pc_audit_report_{stamp}.md")

    report = build_report(redact=True)

    try:
        write_json(json_path, report)
        md = render_markdown(report)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)

        print(f"[pc_audit] Done.")
        print(f"[pc_audit] JSON: {json_path}")
        print(f"[pc_audit] MD  : {md_path}")
        if report.get("meta", {}).get("errors"):
            print(f"[pc_audit] Completed with {len(report['meta']['errors'])} error(s). See meta.errors.")
        else:
            print("[pc_audit] Completed with no recorded errors.")
    except Exception as e:
        print("[pc_audit] FAILED to write outputs.")
        print(str(e))
        print(traceback.format_exc())
