"""Format check for a model folder (revision 5.4: lazy maps, one file open at a time; revision 5.3: memory-mapped reads, no check logic change; revision 5.2: notice-pass listing failure is recorded as ERROR; revision 5.1: check_report() returns structured ERROR instead of raising; otherwise identical to revision 5, 18 Oct 2026: .bin/.pt serialization via the shared serialization.py helper; pickle-named ZIP members or a pickle protocol prefix are UNSUPPORTED with a risk note, never PROBLEM; check_report() adds separate notices. Derived from revision 4, 18 Oct 2026: reference ggml type table, empty-shard and strict-JSON checks; NOT yet tested on a fresh held-out set).

Standard library only; it never imports model code, never unpickles, never loads weights. Every finding has a state:
  PROBLEM      the file is malformed or inconsistent in a way this check can show
  UNSUPPORTED  the check cannot judge this file or this part of it (said explicitly, never reported as clean)
  ERROR        the check itself failed on this file (said explicitly, never reported as clean)
An empty list means only: none of these specific checks found anything; other malformations can still pass. It is not a statement that a runtime can load the
model, that the model behaves as intended, or that it is safe.
"""
import json, mmap, os, struct
from . import serialization_1_1 as serialization  # vendored: package-relative import (only change)


class View:
    """Read-only memory-mapped view of one file: len(), int index, slices (bytes) and startswith(), like bytes.
    Rev 5.3: replaces open(p, "rb").read() for non-JSON files; check logic is unchanged."""
    def __init__(self, path):
        self.path, self.n, self.f, self.m = path, os.path.getsize(path), None, None
    def _open(self):  # rev 5.4: lazy; reopened after close() if a later check needs the file again
        if self.f is None:
            self.f = open(self.path, "rb")
            size = os.fstat(self.f.fileno()).st_size
            if size != self.n: self.close(); raise OSError(f"file changed size during the check ({self.n} -> {size} bytes)")
            self.m = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ) if size else None
    def __len__(self): return self.n
    def __getitem__(self, k):
        if self.n == 0:
            if isinstance(k, int): raise IndexError("empty file")
            return b""
        self._open(); return self.m[k]
    def __bool__(self): return self.n > 0
    def startswith(self, p): return self[: len(p)] == p
    def __contains__(self, b):
        if self.n == 0: return False
        self._open(); return self.m.find(b) != -1
    def seekable_copy(self):
        """A file object positioned at 0 for zipfile (no full copy into memory)."""
        self._open(); self.f.seek(0); return self.f
    def close(self):
        if self.m is not None: self.m.close()
        if self.f is not None: self.f.close()
        self.f = self.m = None


def _load(p, name):
    if name.endswith(".json"):
        with open(p, "rb") as f: return f.read()
    return View(p)


def _head_closed(v, n):
    """First n bytes of a blob; a View is closed again afterwards (rev 5.4)."""
    try: return v[:n]
    finally:
        if isinstance(v, View): v.close()


def _close_all(blobs):
    for v in blobs.values():
        if isinstance(v, View): v.close()


def _inspect(data):
    """serialization.inspect, without copying a mapped ZIP into memory (rev 5.3)."""
    if isinstance(data, View) and data[:2] == b"PK":
        return serialization.inspect_zipfile(data.seekable_copy())
    return serialization.inspect(data)


SAFETENSORS_DTYPES = {"BOOL": 1, "U8": 1, "I8": 1, "F8_E5M2": 1, "F8_E4M3": 1, "I16": 2, "U16": 2, "F16": 2, "BF16": 2,
                      "I32": 4, "U32": 4, "F32": 4, "I64": 8, "U64": 8, "F64": 8}
# ggml type id -> (block size in elements, bytes per block); unknown ids are reported UNSUPPORTED.
# Rev 4: replaced the hand-written table (which had Q8_1 wrong: 36 instead of 40 bytes) with the reference values.
GGML_TYPES = {0: (1, 4), 1: (1, 2), 2: (32, 18), 3: (32, 20), 6: (32, 22), 7: (32, 24), 8: (32, 34), 9: (32, 40),
              10: (256, 84), 11: (256, 110), 12: (256, 144), 13: (256, 176), 14: (256, 210), 15: (256, 292), 16: (256, 66),
              17: (256, 74), 18: (256, 98), 19: (256, 50), 20: (32, 18), 21: (256, 110), 22: (256, 82), 23: (256, 136),
              24: (1, 1), 25: (1, 2), 26: (1, 4), 27: (1, 8), 28: (1, 8), 29: (256, 56), 30: (1, 2), 34: (256, 54),
              35: (256, 66), 39: (32, 17), 40: (64, 36), 41: (128, 18)}  # from gguf 0.19.0 GGML_QUANT_SIZES (rev 4)
WEIGHT_EXT = (".safetensors", ".gguf", ".bin", ".pt", ".pth", ".ckpt")
PICKLE_EXT = (".bin", ".pt", ".pth", ".ckpt")

class Truncated(Exception): pass

class R:
    def __init__(self, data): self.d, self.i = data, 0
    def take(self, n):
        if n < 0 or self.i + n > len(self.d): raise Truncated(f"needs {n} bytes at offset {self.i}, file has {len(self.d)}")
        b = self.d[self.i:self.i + n]; self.i += n; return b
    def u(self, fmt): return struct.unpack("<" + fmt, self.take(struct.calcsize("<" + fmt)))[0]
    def s(self): return self.take(self.u("Q")).decode("utf-8", "replace")

def _f(file, state, detail): return {"file": file, "state": state, "detail": detail}

def _safetensors_header(data):
    if len(data) < 8: raise Truncated("shorter than the 8-byte header length")
    n = struct.unpack("<Q", data[:8])[0]
    if 8 + n > len(data): raise Truncated(f"header length {n} runs past end of file")
    hdr = json.loads(data[8:8 + n])
    if not isinstance(hdr, dict): raise ValueError("header is not a JSON object")
    return n, hdr

def check_safetensors(name, data):
    out = []
    try: n, hdr = _safetensors_header(data)
    except Truncated as e: return [_f(name, "PROBLEM", f"truncated: {e}")]
    except (ValueError, UnicodeDecodeError) as e: return [_f(name, "PROBLEM", f"header is not valid JSON: {e}")]
    body = len(data) - 8 - n
    spans = []
    for t, v in hdr.items():
        if t == "__metadata__": continue
        if not isinstance(v, dict) or not {"dtype", "shape", "data_offsets"} <= v.keys():
            out.append(_f(name, "PROBLEM", f"tensor {t!r}: missing dtype/shape/data_offsets")); continue
        size = SAFETENSORS_DTYPES.get(v["dtype"])
        if size is None: out.append(_f(name, "UNSUPPORTED", f"tensor {t!r}: dtype {v['dtype']} not known to this check")); continue
        shape, offs = v["shape"], v["data_offsets"]
        is_int = lambda x: isinstance(x, int) and not isinstance(x, bool)
        if not (isinstance(shape, list) and all(is_int(d) and d >= 0 for d in shape)):
            out.append(_f(name, "PROBLEM", f"tensor {t!r}: shape must be a list of non-negative integers, got {shape!r}")); continue
        if not (isinstance(offs, list) and len(offs) == 2 and all(is_int(o) and o >= 0 for o in offs)):
            out.append(_f(name, "PROBLEM", f"tensor {t!r}: data_offsets must be two non-negative integers, got {offs!r}")); continue
        a, b = offs; elems = 1
        for d in shape: elems *= d
        if not (0 <= a <= b <= body): out.append(_f(name, "PROBLEM", f"tensor {t!r}: offsets {a}..{b} outside data of {body} bytes"))
        if (b - a) != elems * size: out.append(_f(name, "PROBLEM", f"tensor {t!r}: shape needs {elems * size} bytes, offsets give {b - a}"))
        spans.append((a, b, t))
    spans.sort()
    if spans and spans[0][0] != 0: out.append(_f(name, "PROBLEM", f"{spans[0][0]} unindexed bytes before the first tensor"))
    for (a1, b1, t1), (a2, b2, t2) in zip(spans, spans[1:]):
        if a2 < b1: out.append(_f(name, "PROBLEM", f"tensors {t1!r} and {t2!r} overlap"))
        elif a2 > b1: out.append(_f(name, "PROBLEM", f"{a2 - b1} unindexed bytes between tensors {t1!r} and {t2!r}"))
    end = max((b for _, b, _ in spans), default=0)
    if spans and end != body: out.append(_f(name, "PROBLEM", f"tensor data ends at {end} but file data is {body} bytes"))
    return out

def _gguf_skip_value(r, t):
    fixed = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}
    if t in fixed: r.u(fixed[t]); return
    if t == 8: r.s(); return
    if t == 9:
        at, cnt = r.u("I"), r.u("Q")
        for _ in range(cnt): _gguf_skip_value(r, at)
        return
    raise ValueError(f"unknown metadata value type {t}")

def check_gguf(name, data):
    r = R(data)
    try:
        if r.take(4) != b"GGUF": return [_f(name, "PROBLEM", "bad GGUF magic")]
        ver = r.u("I")
        if ver not in (2, 3): return [_f(name, "UNSUPPORTED", f"GGUF version {ver} not supported by this check")]
        n_tensors, n_kv = r.u("Q"), r.u("Q")
        align = 32
        for _ in range(n_kv):
            key = r.s(); t = r.u("I")
            if key == "general.alignment" and t == 4: align = r.u("I")
            else: _gguf_skip_value(r, t)
        infos = []
        for _ in range(n_tensors):
            tname = r.s(); nd = r.u("I"); dims = [r.u("Q") for _ in range(nd)]; tt = r.u("I"); off = r.u("Q")
            infos.append((tname, dims, tt, off))
    except Truncated as e: return [_f(name, "PROBLEM", f"truncated GGUF header or tensor table: {e}")]
    except ValueError as e: return [_f(name, "UNSUPPORTED", str(e))]
    out = []
    data_start = (r.i + align - 1) // align * align
    for tname, dims, tt, off in infos:
        if tt not in GGML_TYPES: out.append(_f(name, "UNSUPPORTED", f"tensor {tname!r}: ggml type {tt} not known to this check")); continue
        blk, bpb = GGML_TYPES[tt]; elems = 1
        for d in dims: elems *= d
        if elems % blk: out.append(_f(name, "PROBLEM", f"tensor {tname!r}: {elems} elements not a multiple of block {blk}")); continue
        if data_start + off + elems // blk * bpb > len(data):
            out.append(_f(name, "PROBLEM", f"tensor {tname!r}: data runs past end of file (truncated)"))
    return out

def _strict_json(b):
    def bad(c): raise ValueError(f"non-standard JSON constant {c}")
    return json.loads(b, parse_constant=bad)

def check(folder, require_template=False, strict_json=False):
    """Return findings for one model folder. require_template: the user's workflow needs a chat template.
    strict_json: reject NaN/Infinity, which Python accepts but strict JSON parsers do not (rev 4)."""
    out = []
    try: names = sorted(os.listdir(folder))
    except OSError as e: return [_f(folder, "ERROR", f"cannot list folder: {e}")]
    blobs = {}
    try:
        return _check(folder, names, blobs, out, require_template, strict_json)
    finally:
        _close_all(blobs)


def _check(folder, names, blobs, out, require_template, strict_json):
    for name in names:
        p = os.path.join(folder, name)
        if not os.path.isfile(p): continue
        data = None
        try:
            data = _load(p, name); blobs[name] = data
            if name.endswith(WEIGHT_EXT):
                if not data: out.append(_f(name, "PROBLEM", "empty weights file")); continue
                if data.startswith(b"version https://git-lfs"): out.append(_f(name, "PROBLEM", "Git LFS pointer, not the weights")); continue
            if name.endswith(PICKLE_EXT):
                # Rev 5: shared helper. Serialization risk is not a format defect, so it is never PROBLEM here.
                r = _inspect(data)
                out.append(_f(name, "UNSUPPORTED", ("not structurally checked; " + r["detail"]) if r["risk"] else r["detail"]))
            if name.endswith(".safetensors"): out += check_safetensors(name, data)
            if name.endswith(".gguf"): out += check_gguf(name, data)
            if name.endswith(".json"):
                try: obj = _strict_json(data) if strict_json else json.loads(data)
                except (ValueError, UnicodeDecodeError) as e: out.append(_f(name, "PROBLEM", f"invalid JSON: {e}")); continue
                if name in ("config.json", "tokenizer_config.json", "model.safetensors.index.json") and not isinstance(obj, dict):
                    out.append(_f(name, "PROBLEM", "expected a JSON object"))
        except Exception as e:
            out.append(_f(name, "ERROR", f"check failed: {type(e).__name__}: {e}"))
        finally:
            if isinstance(data, View): data.close()  # rev 5.4: one file mapped at a time
    # Sharded safetensors: each referenced shard exists and holds the tensors the index assigns to it.
    if "model.safetensors.index.json" in blobs:
        try:
            idx = json.loads(blobs["model.safetensors.index.json"]); wm = idx.get("weight_map", {}) if isinstance(idx, dict) else {}
            for shard in sorted(set(wm.values())):
                if shard not in blobs: out.append(_f("model.safetensors.index.json", "PROBLEM", f"references missing shard {shard}")); continue
                try: _, hdr = _safetensors_header(blobs[shard])
                except Exception: continue  # the shard's own finding already covers it
                finally:
                    if isinstance(blobs[shard], View): blobs[shard].close()
                if not [k for k in hdr if k != "__metadata__"]:
                    out.append(_f("model.safetensors.index.json", "PROBLEM", f"{shard} holds no tensors (empty shard in a sharded set)"))
                for tensor in sorted(k for k, s in wm.items() if s == shard):
                    if tensor not in hdr: out.append(_f("model.safetensors.index.json", "PROBLEM", f"tensor {tensor!r} not found in {shard}"))
        except Exception as e:
            out.append(_f("model.safetensors.index.json", "ERROR", f"check failed: {type(e).__name__}: {e}"))
    # Rev 4: a file named like a shard of a set (model-0000k-of-0000n.safetensors) that holds no tensors.
    import re as _re
    for n in names:
        if _re.search(r"-\d{5}-of-\d{5}\.safetensors$", n) and n in blobs:
            try:
                _, hdr = _safetensors_header(blobs[n])
                if not [k for k in hdr if k != "__metadata__"]: out.append(_f(n, "PROBLEM", "shard of a sharded set holds no tensors"))
            except Exception: pass
            finally:
                if isinstance(blobs[n], View): blobs[n].close()
    # Chat template: only when the workflow needs one; it may live inline or in a separate file.
    if require_template:
        inline = False
        try:
            tc = json.loads(blobs.get("tokenizer_config.json", b"{}"))
            inline = isinstance(tc, dict) and bool(tc.get("chat_template"))
        except Exception: pass
        separate = any(n in blobs for n in ("chat_template.jinja", "chat_template.json"))
        in_gguf = any(n.endswith(".gguf") and b"tokenizer.chat_template" in _head_closed(blobs[n], 4_000_000) for n in blobs)
        if not (inline or separate or in_gguf):
            out.append(_f("(folder)", "PROBLEM", "workflow needs a chat template; none inline, in a separate file, or in GGUF metadata"))
    return out


REVISION = "5.4"
def check_report(folder, require_template=False, strict_json=False):
    """Findings (PROBLEM / UNSUPPORTED / ERROR, exactly as check()) plus separate serialization risk notices.
    Rev 5.1: never raises on unavailable or unreadable input; such failures are ERROR findings and the report is
    still returned. Notices are heuristics (pickle-named ZIP member or recognized protocol prefix); nothing is loaded
    or validated."""
    findings = check(folder, require_template=require_template, strict_json=strict_json)
    report = {"revision": REVISION, "serialization": serialization.VERSION, "findings": findings, "notices": []}
    try: names = sorted(os.listdir(folder))
    except OSError as e:
        # Rev 5.2: the first scan may have succeeded; never return silently without an ERROR.
        if not any(x["state"] == "ERROR" and x["detail"].startswith("cannot list folder") for x in findings):
            findings.append(_f(folder, "ERROR", f"serialization notice pass cannot list folder: {e}"))
        return report
    for name in names:
        if not name.endswith(PICKLE_EXT): continue
        p = os.path.join(folder, name)
        try:
            if not os.path.isfile(p): continue
            data = View(p)
            try:
                if data and not data.startswith(b"version https://git-lfs"):
                    r = _inspect(data)
                    if r["risk"]: report["notices"].append({"file": name, "kind": r["kind"], "detail": r["detail"]})
            finally: data.close()
        except Exception as e:
            findings.append(_f(name, "ERROR", f"serialization notice scan failed: {type(e).__name__}: {e}"))
    return report
