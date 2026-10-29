"""
Archive Password Recovery — desktop app.

A native window (pywebview + Edge WebView2) showing a web UI, driving the
hashcat engine in engine.py. Recovers passwords for RAR/PDF files you own or
are authorized to open.
"""
import os
import sys
import json
import threading

import webview

import engine


def _res(*parts):
    """Path to a bundled resource, from source and from the PyInstaller exe."""
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) \
        else os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, *parts)


# rough single-GPU hash-rate baselines (H/s) per hashcat mode
SPEED_EST = {13000: 20000, 10400: 4_000_000, 10500: 4_000_000,
             10600: 45000, 10700: 45000}
DEV_FACTOR = {"cpu": 0.12, "gpu": 1.0, "both": 1.08}
PERF_FACTOR = {1: 0.85, 2: 1.0, 3: 1.06, 4: 1.12}
RULE_MULT = 77  # best64.rule expands each word ~77x


def _human_eta(seconds):
    if seconds <= 0 or seconds != seconds:  # 0 or NaN
        return "instant", "ok"
    if seconds < 60:
        return "seconds", "ok"
    if seconds < 3600:
        return f"~{int(seconds // 60)} min", "ok"
    if seconds < 86400:
        return f"~{int(seconds // 3600)} hours", "med"
    if seconds < 86400 * 365:
        return f"~{int(seconds // 86400)} days", "med"
    years = seconds / (86400 * 365)
    if years < 1000:
        return f"~{int(years)} years", "slow"
    return "effectively forever", "slow"


class Api:
    def __init__(self):
        self.window = None
        self.job = None
        self._last = None          # params of the running attack, for resume
        self._hash = None
        self._mode = None

    # ---------- device detection (non-blocking: never stalls the UI thread) ----------
    def get_devices(self):
        def work():
            res = {"cpu": False, "gpu": False}
            try:
                for d in engine.detect_devices():
                    t = (d.get("type") or "").upper()
                    if "GPU" in t:
                        res["gpu"] = True
                    elif "CPU" in t:
                        res["cpu"] = True
            except Exception:  # noqa
                pass
            self._push("onDevices", res)
        threading.Thread(target=work, daemon=True).start()
        return {"pending": True}

    # ---------- file selection + hash extraction ----------
    def pick_file(self):
        sel = self.window.create_file_dialog(
            webview.OPEN_DIALOG, allow_multiple=False,
            file_types=("Archives (*.rar;*.pdf)", "All files (*.*)"),
        )
        if not sel:
            return None
        path = sel[0] if isinstance(sel, (list, tuple)) else sel
        name = os.path.basename(path)
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        try:
            h, mode, label = engine.extract_hash(path)
        except Exception as e:  # noqa — surface a clean message to the UI
            return {"ok": False, "name": name, "error": str(e)}
        self._hash, self._mode = h, mode
        return {"ok": True, "path": path, "name": name,
                "size": _fmt_size(size), "format": label, "mode": mode}

    def pick_wordlist(self):
        sel = self.window.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=False)
        if not sel:
            return None
        path = sel[0] if isinstance(sel, (list, tuple)) else sel
        return {"path": path, "name": os.path.basename(path)}

    # ---------- feasibility estimate ----------
    def estimate(self, p):
        mode = p.get("mode") or 13000
        base = SPEED_EST.get(mode, 20000)
        speed = base * DEV_FACTOR.get(p.get("device", "both"), 1.0) \
            * PERF_FACTOR.get(int(p.get("perf", 2)), 1.0)
        if p.get("attack") == "brute":
            pool = p.get("pool", "")
            ks = engine.keyspace_pool(pool, int(p.get("min_len", 1)), int(p.get("max_len", 8)))
            eta = (ks / speed) if speed else 0
            label, feas = _human_eta(eta)
            return {"keyspace": ks, "pool_size": len(set(pool)),
                    "eta_label": label, "feas": feas, "speed": int(speed)}
        return {"keyspace": 0, "eta_label": "depends on wordlist", "feas": "ok"}

    # ---------- attack lifecycle ----------
    def _make_job(self):
        return engine.CrackJob(
            on_status=lambda s: self._push("onStatus", s),
            on_log=lambda m: self._push("onLog", m),
            on_finish=lambda r: self._push("onFinish", r),
        )

    def _build_cmd(self, job, p):
        dev = p.get("device", "both")
        wl = p.get("perf", 2)
        if p.get("attack") == "wordlist":
            rule = _res("hashcat", "best64.rule") if p.get("use_rules") else None
            return job.build_wordlist(p["wordlist"], rule, dev, wl)
        return job.build_bruteforce_pool(
            p.get("pool", ""), int(p.get("min_len", 1)),
            int(p.get("max_len", 8)), dev, wl)

    def start(self, p):
        if self._hash is None or self._mode is None:
            return {"error": "No file loaded — choose a file first."}
        if p.get("attack") == "wordlist" and not (p.get("wordlist") and os.path.isfile(p["wordlist"])):
            return {"error": "Select a valid wordlist file."}
        if p.get("attack") == "brute":
            mn, mx = int(p.get("min_len", 1)), int(p.get("max_len", 8))
            if not (1 <= mn <= mx <= 32):
                return {"error": "Length range must be 1–32 with 'from' ≤ 'to'."}
            if not p.get("pool"):
                return {"error": "Pick at least one character to try."}
        # fresh job + hash file
        self.job = self._make_job()
        self.job.mode = self._mode
        try:
            with open(self.job.hash_file, "w", encoding="utf-8") as f:
                f.write(self._hash + "\n")
        except OSError as e:
            return {"error": f"Could not write hash file: {e}"}
        try:
            cmd = self._build_cmd(self.job, p)
        except Exception as e:  # noqa
            return {"error": str(e)}
        self._last = dict(p)
        self.job.start(cmd, resume=False)
        return {"ok": True}

    def pause(self):
        if self.job:
            threading.Thread(target=self.job.pause, daemon=True).start()
        return {"ok": True}

    def resume(self):
        if not self.job or not engine.CrackJob.can_resume():
            return {"error": "Nothing to resume — the run had not saved a checkpoint yet."}
        self.job = self._make_job()
        self.job.mode = self._mode
        self.job.start([], resume=True)
        return {"ok": True}

    def stop(self):
        if self.job:
            self.job.stop()
        return {"ok": True}

    def shutdown(self):
        if self.job:
            try:
                self.job.stop()
            except Exception:  # noqa
                pass

    # ---------- push events into the page ----------
    def _push(self, fn, payload):
        if not self.window:
            return
        try:
            self.window.evaluate_js(f"window.AR && window.AR.{fn}({json.dumps(payload)})")
        except Exception:  # noqa — window may be closing
            pass


def _fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def main():
    api = Api()
    window = webview.create_window(
        "Archive Password Recovery",
        _res("ui", "index.html"),
        js_api=api, width=1180, height=940, min_size=(820, 640),
        background_color="#0b0d13",
    )
    api.window = window
    window.events.closed += api.shutdown
    # persist the WebView2 profile so repeat launches warm up fast (no cold-start freeze)
    store = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                         "ArchiveRecovery", "webview")
    try:
        os.makedirs(store, exist_ok=True)
    except OSError:
        store = None
    webview.start(gui="edgechromium", private_mode=False, storage_path=store)


def _selftest(pdf_path, out_path=None):
    """Headless check that hash extraction works in this (possibly frozen) build.
    Usage: ArchiveRecovery.exe --selftest <file> [resultfile]"""
    try:
        h, mode, label = engine.extract_hash(pdf_path)
        msg = f"OK {label} mode={mode} {h[:40]}"
    except Exception as e:  # noqa
        msg = f"FAIL {e}"
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(msg)
        except OSError:
            pass
    return 0 if msg.startswith("OK") else 1


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--selftest":
        sys.exit(_selftest(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None))
    main()
