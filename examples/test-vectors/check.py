#!/usr/bin/env python3
"""Verify canonicalization-vectors.json against its harness_contract.

Python 3 stdlib only (mirrors AIVS §1.2; runs on 3.8+). Exit 0 if every vector
recomputes and every mustEqual/mustDifferFrom/collidesWith invariant holds, else 1.

    python3 check.py [path-to-vectors.json]   # defaults to the sibling file
"""
import hashlib, json, struct, sys, unicodedata
from pathlib import Path

ORDER = ["row_id", "session_id", "action_type", "tool_name", "cost_cents",
         "timestamp", "prev_hash", "input_hash", "output_hash"]
STR = {"session_id", "action_type", "tool_name", "timestamp", "prev_hash",
       "input_hash", "output_hash"}


def jcs(v):  # RFC 8785 for the ASCII-string/integer/object inputs used here
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def inner(v):
    if v.get("construction", "jcs") == "empty":
        return hashlib.sha256(b"").hexdigest()           # "output absent" sentinel (#11)
    return hashlib.sha256(jcs(v["input"])).hexdigest()


def row(v):
    form = v.get("form", "NFC")
    r = {k: (unicodedata.normalize(form, str(x)) if k in STR else x) for k, x in v["row"].items()}
    if v.get("prohibitedTransform"):
        r["tool_name"] = unicodedata.normalize(v["prohibitedTransform"], str(v["row"]["tool_name"]))
    return hashlib.sha256(b"".join(struct.pack(">I", len(b)) + b
                                   for b in (str(r[f]).encode() for f in ORDER))).hexdigest()


def index(vectors, fails):
    """name -> vector, recording duplicate or missing names as failures."""
    m = {}
    for i, v in enumerate(vectors):
        name = v.get("name")
        if not name:
            fails.append("vector #%d is missing 'name'" % i)
        elif name in m:
            fails.append("duplicate vector name %r" % name)
        else:
            m[name] = v
    return m


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("canonicalization-vectors.json")
    d = json.loads(path.read_text(encoding="utf-8"))
    fails = []
    ih, rh = index(d["inner_hash_vectors"], fails), index(d["row_hash_vectors"], fails)

    def ref(table, name, who, kind):  # resolve an invariant reference or record a failure
        if name not in table:
            fails.append("%s: %s references unknown vector %r" % (who, kind, name))
            return None
        return table[name]

    for v in d["inner_hash_vectors"]:
        got = "sha256:" + inner(v)
        if got != v["expectedHash"]:
            fails.append("%s: got %s want %s" % (v.get("name", "?"), got, v["expectedHash"]))
        me = v.get("mustEqual")
        if me:
            t = ref(ih, me, v.get("name"), "mustEqual")
            if t and v["expectedHash"] != t["expectedHash"]:
                fails.append("%s mustEqual %s" % (v.get("name"), me))

    for v in d["row_hash_vectors"]:
        got = "sha256:" + row(v)
        if got != v["expectedRowHash"]:
            fails.append("%s: got %s want %s" % (v.get("name", "?"), got, v["expectedRowHash"]))
        for kind, same in (("mustDifferFrom", False), ("collidesWith", True)):
            other = v.get(kind)
            if other:
                t = ref(rh, other, v.get("name"), kind)
                if t and (v["expectedRowHash"] == t["expectedRowHash"]) != same:
                    fails.append("%s %s %s" % (v.get("name"), kind, other))

    n = len(d["inner_hash_vectors"]) + len(d["row_hash_vectors"])
    for f in fails:
        print("FAIL " + f, file=sys.stderr)
    print("%d vectors checked, %d failures" % (n, len(fails)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
