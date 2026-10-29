"""
Archive Password Recovery — engine.
Thin, honest wrapper around hashcat (mode 13000 = RAR5, 10400-10700 = PDF).
Handles hash extraction, attack building, CPU/GPU/Both selection, workload
throttle, start/pause/resume/stop, and live status from hashcat --status-json.

Only recovers passwords for archives you own or are authorized to open.
"""
import json
import mmap
import os
import signal
import subprocess
import sys
import threading
import time


# ---------- locate bundled hashcat (works from source and from PyInstaller exe) ----------
def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def hashcat_dir():
    return os.path.join(app_dir(), "hashcat")


def hashcat_exe():
    return os.path.join(hashcat_dir(), "hashcat.exe")


# per-process namespace so two running instances never share hash/found/session files
_PID = os.getpid()
SESSION = f"arpr_{_PID}"


def restore_file():
    return os.path.join(hashcat_dir(), SESSION + ".restore")


CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200


# ---------- RAR5 hash extraction ($rar5$...) ----------
RAR5_SIG = bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00])


def _vint(buf, p):
    shift = 0
    val = 0
    while True:
        b = buf[p]
        p += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return val, p


def _parse_block(buf, p):
    p += 4  # skip CRC32
    hsize, p = _vint(buf, p)
    hdr_start = p
    htype, p = _vint(buf, p)
    hflags, p = _vint(buf, p)
    extra_size = 0
    data_size = 0
    if hflags & 0x0001:
        extra_size, p = _vint(buf, p)
    if hflags & 0x0002:
        data_size, p = _vint(buf, p)
    hdr_end = hdr_start + hsize
    return {
        "type": htype,
        "flags": hflags,
        "extra_start": hdr_end - extra_size,
        "hdr_end": hdr_end,
    }, hdr_end + data_size


def extract_rar5_hash(path):
    """Return a hashcat mode-13000 hash string, or raise ValueError.
    Scans the whole file (mmap) so a deep first-file header is still found."""
    if os.path.getsize(path) < 8:
        raise ValueError("File too small to be a RAR archive.")
    with open(path, "rb") as f:
        if f.read(8) != RAR5_SIG:
            raise ValueError("Not a RAR5 archive (RAR4 / other formats not supported yet).")
        f.seek(0)
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            p = 8
            n = len(data)
            while p < n:
                try:
                    blk, nxt = _parse_block(data, p)
                except (IndexError, ValueError):
                    break
                if (blk["type"] in (2, 3) and blk["flags"] & 0x0001
                        and blk["extra_start"] < blk["hdr_end"] <= n):
                    ep = blk["extra_start"]
                    while ep < blk["hdr_end"]:
                        rsize, q = _vint(data, ep)
                        rec_end = q + rsize
                        rtype, q = _vint(data, q)
                        if rtype == 1:  # FHEXTRA_CRYPT
                            _ver, q = _vint(data, q)
                            flags, q = _vint(data, q)
                            kdf = data[q]; q += 1
                            salt = data[q:q + 16]; q += 16
                            iv = data[q:q + 16]; q += 16
                            if not (flags & 0x0001):
                                raise ValueError("Archive has no password verifier; cannot build hash.")
                            check = data[q:q + 12]
                            return (f"$rar5$16${salt.hex()}${kdf}${iv.hex()}"
                                    f"$8${check[:8].hex()}")
                        ep = rec_end
                if nxt <= p:
                    break
                p = nxt
    raise ValueError("No encryption header found — is the archive actually password-protected?")


# ---------- PDF hash extraction (native, via pypdf — no external script) ----------
def _pdf_bytes(x):
    return x.original_bytes if hasattr(x, "original_bytes") else bytes(x)


def extract_pdf_hash(path):
    """Return ($pdf$..., hashcat_mode) for an encrypted PDF, built directly from
    its /Encrypt dictionary. Format matches hashcat modes 10400-10700."""
    try:
        from pypdf import PdfReader
    except ImportError:
        raise ValueError("PDF support unavailable (pypdf not installed).")
    try:
        reader = PdfReader(path)
    except Exception as e:  # noqa — malformed / not a PDF
        raise ValueError(f"Could not read PDF: {e}")
    if not reader.is_encrypted:
        raise ValueError("This PDF is not password-protected.")
    try:
        enc = reader.trailer["/Encrypt"].get_object()
    except Exception:
        raise ValueError("PDF has no encryption dictionary.")

    V = int(enc.get("/V", 0))
    R = int(enc.get("/R", 0))
    length = int(enc.get("/Length", 40))
    P = int(enc["/P"])
    if P > 0x7FFFFFFF:            # store as signed 32-bit, as hashcat expects
        P -= 0x100000000
    enc_meta = 1 if enc.get("/EncryptMetadata", True) else 0
    O = _pdf_bytes(enc["/O"])
    U = _pdf_bytes(enc["/U"])
    id_obj = reader.trailer.get("/ID")
    id0 = _pdf_bytes(id_obj[0]) if id_obj else b""

    if V >= 5:                    # AES-256, R5 (10600) / R6 (10700): U,O = 48B, UE,OE = 32B
        UE = _pdf_bytes(enc["/UE"])
        OE = _pdf_bytes(enc["/OE"])
        h = ("$pdf$%d*%d*%d*%d*%d*%d*%s*%d*%s*%d*%s*%d*%s*%d*%s" % (
            V, R, length, P, enc_meta, len(id0), id0.hex(),
            len(U), U.hex(), len(O), O.hex(),
            len(UE), UE.hex(), len(OE), OE.hex()))
        mode = 10600 if R == 5 else 10700
    else:                         # RC4 / AES-128, R2/3/4: U,O = 32B
        U, O = U[:32], O[:32]
        h = ("$pdf$%d*%d*%d*%d*%d*%d*%s*%d*%s*%d*%s" % (
            V, R, length, P, enc_meta, len(id0), id0.hex(),
            len(U), U.hex(), len(O), O.hex()))
        mode = {2: 10400, 3: 10500, 4: 10500}.get(R, 10500)
    return h, mode


# ---------- dispatch by file type ----------
def extract_hash(path):
    """Return (hash_string, hashcat_mode, format_label). Raises ValueError."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".rar":
        return extract_rar5_hash(path), 13000, "RAR5 (AES-256)"
    if ext == ".pdf":
        h, mode = extract_pdf_hash(path)
        return h, mode, f"PDF (hashcat {mode})"
    raise ValueError(f"Unsupported file type '{ext}'. Supported: .rar, .pdf")


# ---------- charset helpers for brute force ----------
CHARSETS = {"lower": "?l", "upper": "?u", "digits": "?d", "symbols": "?s"}
CHARSET_SIZE = {"lower": 26, "upper": 26, "digits": 10, "symbols": 33}


def build_custom_charset(selected):
    if set(selected) >= {"lower", "upper", "digits", "symbols"}:
        return "?a", None
    parts = "".join(CHARSETS[k] for k in selected if k in CHARSETS)
    return "?1", parts


def brute_keyspace(selected, min_len, max_len):
    """Total candidate count for a brute-force range (for the feasibility pill)."""
    size = sum(CHARSET_SIZE[k] for k in selected if k in CHARSET_SIZE)
    if size == 0 or max_len < min_len or min_len < 1:
        return 0
    return sum(size ** n for n in range(min_len, max_len + 1))


def escape_charset(chars):
    """Build a hashcat -1 literal charset. '?' must be doubled so it isn't read
    as a mask token."""
    return "".join(c + c if c == "?" else c for c in chars)


def keyspace_pool(pool, min_len, max_len):
    """Total candidates for an explicit character pool (custom selection)."""
    size = len(set(pool))
    if size == 0 or max_len < min_len or min_len < 1:
        return 0
    return sum(size ** n for n in range(min_len, max_len + 1))


# ---------- device detection ----------
def detect_devices():
    """Return [{'type':'GPU'|'CPU', 'name':str}] from hashcat -I."""
    try:
        out = subprocess.run(
            [hashcat_exe(), "-I"], cwd=hashcat_dir(),
            capture_output=True, text=True, timeout=60,
            creationflags=CREATE_NO_WINDOW,
        ).stdout
    except Exception:  # noqa
        return []
    devs = []
    cur = {}
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Type"):
            cur["type"] = s.split(":", 1)[1].strip().upper() if ":" in s else "?"
        elif s.startswith("Name"):
            cur["name"] = s.split(":", 1)[1].strip() if ":" in s else "?"
            if "type" in cur and "name" in cur:
                devs.append({"type": cur.get("type", "?"), "name": cur["name"]})
            cur = {}
    return devs


def list_devices():
    devs = detect_devices()
    if not devs:
        return "(no compute devices detected)"
    return "\n".join(f"{d['type']}: {d['name']}" for d in devs)


# ---------- the job ----------
class CrackJob:
    """Runs one hashcat attack with live status + pause/resume."""

    SESSION = SESSION

    def __init__(self, on_status=None, on_log=None, on_finish=None):
        self.on_status = on_status or (lambda s: None)
        self.on_log = on_log or (lambda m: None)
        self.on_finish = on_finish or (lambda result: None)
        self.proc = None
        self._thread = None
        self._stop = False
        self.mode = 13000
        self.hash_file = os.path.join(hashcat_dir(), f"arpr_hash_{_PID}.txt")
        self.out_file = os.path.join(hashcat_dir(), f"arpr_found_{_PID}.txt")

    # ---- command construction ----
    def _device_flag(self, mode):
        return {"cpu": ["-D", "1"], "gpu": ["-D", "2"], "both": ["-D", "1,2"]}[mode]

    def _base_cmd(self, device_mode, workload):
        return [
            hashcat_exe(), "-m", str(self.mode),
            self.hash_file,
            "-w", str(workload),
            *self._device_flag(device_mode),
            "--status", "--status-json", "--status-timer", "2",
            "--potfile-disable",
            "-o", self.out_file,
            "--session", self.SESSION,
        ]

    def build_bruteforce(self, charsets, min_len, max_len, device_mode, workload):
        mask_token, custom = build_custom_charset(charsets)
        cmd = self._base_cmd(device_mode, workload)
        cmd += ["-a", "3"]
        if custom:
            cmd += ["-1", custom]
        cmd += ["-i", "--increment-min", str(min_len)]
        cmd += [mask_token * max_len]
        return cmd

    def build_bruteforce_pool(self, pool, min_len, max_len, device_mode, workload):
        """Brute force over an explicit set of characters the user picked."""
        uniq = "".join(dict.fromkeys(pool))  # dedup, keep order
        cmd = self._base_cmd(device_mode, workload)
        cmd += ["-a", "3", "-1", escape_charset(uniq)]
        cmd += ["-i", "--increment-min", str(min_len)]
        cmd += ["?1" * max_len]
        return cmd

    def build_wordlist(self, wordlist, rule, device_mode, workload):
        cmd = self._base_cmd(device_mode, workload)
        cmd += ["-a", "0", os.path.abspath(wordlist)]
        if rule and os.path.exists(rule):
            cmd += ["-r", rule]
        return cmd

    # ---- lifecycle ----
    @staticmethod
    def can_resume():
        return os.path.exists(restore_file())

    def start(self, cmd, resume=False):
        if resume:
            if not self.can_resume():
                self.on_log("[resume] nothing to resume — no checkpoint written yet; start a new run.")
                self.on_finish({"status": "no_restore",
                                "message": "nothing to resume — start a new run"})
                return
            cmd = [hashcat_exe(), "--session", self.SESSION, "--restore"]
        else:
            for f in (self.out_file, restore_file()):
                try:
                    os.remove(f)
                except OSError:
                    pass
        self._stop = False
        self._thread = threading.Thread(target=self._run, args=(cmd,), daemon=True)
        self._thread.start()

    def _run(self, cmd):
        # keep the raw command out of the user-facing log; expose it only as debug
        self.on_log("[debug] " + " ".join(f'"{c}"' if " " in c else c for c in cmd))
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=hashcat_dir(),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
            )
        except Exception as e:  # noqa
            self.on_log(f"[error] could not launch hashcat: {e}")
            self.on_finish({"status": "error", "message": str(e)})
            return

        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{") and '"status"' in line:
                self._handle_status(line)
            else:
                self.on_log(line)

        rc = self.proc.wait()
        result = self._read_result()
        if result["status"] == "cracked":
            pass
        elif self._stop:
            result["status"] = "paused_or_stopped"
        elif rc not in (0, 1):
            # hashcat: 0=cracked, 1=exhausted; anything else = real failure
            result["status"] = "error"
            result["message"] = (
                f"hashcat exited with code {rc} — see log above. Likely no compute "
                f"device for the selected mode, or a kernel-build / self-test failure.")
        self.on_finish(result)

    def _handle_status(self, line):
        try:
            s = json.loads(line)
        except json.JSONDecodeError:
            return
        devices = s.get("devices", [])
        speed = sum(d.get("speed", 0) for d in devices)
        prog = s.get("progress", [0, 0])
        cur, total = (list(prog) + [0, 0])[:2]
        pct = (cur / total * 100.0) if total else 0.0
        est = s.get("estimated_stop", 0)
        eta = max(0, est - int(time.time())) if est else 0
        self.on_status({
            "speed": speed, "cur": cur, "total": total, "pct": pct,
            "eta": eta, "status_code": s.get("status", 0),
            "recovered": (s.get("recovered_hashes") or [0])[0],
        })

    def _read_result(self):
        cracked = os.path.exists(self.out_file) and os.path.getsize(self.out_file) > 0
        pw = None
        if cracked:
            raw = open(self.out_file, "r", encoding="utf-8", errors="ignore").read().rstrip("\r\n")
            pw = raw.split(":", 1)[1] if ":" in raw else ""
            try:
                os.remove(self.out_file)  # don't leave recovered plaintext on disk
            except OSError:
                pass
        return {"status": "cracked" if cracked else "done", "password": pw}

    # ---- controls ----
    def pause(self):
        """Ask hashcat to stop gracefully so it flushes a .restore; hard-kill as fallback."""
        self._stop = True
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
                self.proc.wait(timeout=10)
                return
            except (ValueError, OSError, subprocess.TimeoutExpired):
                pass
        self._kill()

    def stop(self):
        self._stop = True
        self._kill()
        for f in (restore_file(), self.hash_file, self.out_file):
            try:
                os.remove(f)
            except OSError:
                pass

    def _kill(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:  # noqa
                pass
