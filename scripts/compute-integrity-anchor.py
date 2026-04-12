#!/usr/bin/env python3
"""Phase 7.0: multi-source anchor = SHA256( preimage_utf8 || 32*0 ); preimage = machine-id\\ncpu\\nroot-uuid (normalized)."""
import hashlib
import pathlib
import subprocess
import sys


def norm(s: str) -> str:
    return s.strip().lower()


def first_cpu_block(text: str) -> dict[str, str]:
    m: dict[str, str] = {}
    saw_processor = False
    for line in text.splitlines():
        ls = line.strip()
        if not ls:
            if m:
                break
            continue
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if k == "processor":
            if saw_processor and m:
                break
            saw_processor = True
            continue
        if saw_processor:
            m[k] = v
    return m


def cpu_identity(cpuinfo: str) -> str:
    blk = first_cpu_block(cpuinfo)
    if not blk:
        raise SystemExit("integrity: cpuinfo: no processor block")
    if blk.get("serial"):
        return blk["serial"]
    if blk.get("model name"):
        return blk["model name"]
    parts = []
    for key in ("vendor_id", "cpu family", "model", "model name"):
        if blk.get(key):
            parts.append(blk[key].strip())
    if not parts:
        raise SystemExit("integrity: cpuinfo: no serial, model name, or vendor tuple")
    return "|".join(parts)


def root_uuid() -> str:
    try:
        u = subprocess.check_output(["findmnt", "-n", "-o", "UUID", "/"], text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        u = ""
    nu = norm(u)
    if nu and nu != "unknown":
        return u
    try:
        src = subprocess.check_output(["findmnt", "-n", "-o", "SOURCE", "/"], text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return uuid_from_proc_mounts()
    sl = src.lower()
    if sl.startswith("uuid="):
        return src.split("=", 1)[1].strip()
    try:
        out = subprocess.check_output(["blkid", "-o", "value", "-s", "UUID", src], text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        out = ""
    if out:
        return out
    return uuid_from_proc_mounts()


def uuid_from_proc_mounts() -> str:
    for line in pathlib.Path("/proc/mounts").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "/":
            dev = fields[0]
            sl = dev.lower()
            if sl.startswith("uuid="):
                return dev.split("=", 1)[1]
            try:
                out = subprocess.check_output(
                    ["blkid", "-o", "value", "-s", "UUID", dev], text=True
                ).strip()
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
            if out:
                return out
    raise SystemExit("integrity: root filesystem UUID unavailable")


def anchor_history_first_line(anchor_digest: bytes) -> str:
    """Phase 7.2: H(n)=SHA256(anchor||H(n-1)), H(0)=0^32."""
    h = hashlib.sha256(anchor_digest + bytes(32)).digest()
    return f"anchor:{anchor_digest.hex()} hash:{h.hex()}\n"


def main() -> None:
    if len(sys.argv) not in (2, 3):
        print(
            "usage: compute-integrity-anchor.py <anchor-out> [<anchor.history-out>]",
            file=sys.stderr,
        )
        sys.exit(2)
    out_path = pathlib.Path(sys.argv[1])
    mid_n = norm(pathlib.Path("/etc/machine-id").read_text())
    if not mid_n:
        raise SystemExit("integrity: machine-id empty")
    cpu_n = norm(cpu_identity(pathlib.Path("/proc/cpuinfo").read_text()))
    if not cpu_n:
        raise SystemExit("integrity: cpu identity empty")
    u_n = norm(root_uuid())
    if not u_n:
        raise SystemExit("integrity: root uuid empty")
    material = f"{mid_n}\n{cpu_n}\n{u_n}".encode()
    digest = hashlib.sha256(material + bytes(32)).digest()
    out_path.write_bytes(digest)
    if len(sys.argv) == 3:
        pathlib.Path(sys.argv[2]).write_text(anchor_history_first_line(digest))


if __name__ == "__main__":
    main()
