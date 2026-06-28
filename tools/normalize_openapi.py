#!/usr/bin/env python3
"""Normalize a FastAPI OpenAPI 3.1 spec into an oapi-codegen-friendly 3.0 one.

oapi-codegen (v2.x) does not understand OpenAPI 3.1's nullable idioms:
  - schema `anyOf:[{...}, {type:null}]`  (FastAPI's Optional[...] form)
  - schema `oneOf:[{...}, {type:null}]`
  - JSON-Schema `type:[ "x", "null" ]`

This collapses each into 3.0's `{"...": ..., "nullable": true}`, drops any bare
`{type:null}` members, and stamps `openapi: 3.0.3`. Deterministic, no deps.

Usage: normalize_openapi.py <in.json> <out.json>
"""
import json
import sys


def _is_null_schema(s):
    return isinstance(s, dict) and s.get("type") == "null" and len(s) == 1


def normalize(node):
    if isinstance(node, list):
        return [normalize(x) for x in node]
    if not isinstance(node, dict):
        return node

    node = {k: normalize(v) for k, v in node.items()}

    # type: ["string", "null"] -> type: "string", nullable: true
    t = node.get("type")
    if isinstance(t, list):
        non_null = [x for x in t if x != "null"]
        if "null" in t:
            node["nullable"] = True
        node["type"] = non_null[0] if len(non_null) == 1 else non_null

    # anyOf / oneOf containing a {type:null} member -> nullable + collapse
    for key in ("anyOf", "oneOf"):
        variants = node.get(key)
        if not isinstance(variants, list):
            continue
        has_null = any(_is_null_schema(v) for v in variants)
        remaining = [v for v in variants if not _is_null_schema(v)]
        if not has_null:
            continue
        node["nullable"] = True
        if len(remaining) == 1 and isinstance(remaining[0], dict):
            # Merge the single real variant up, preserving sibling keys
            # (description/title/etc.) that already live on this node.
            merged = dict(remaining[0])
            del node[key]
            for k, v in merged.items():
                node.setdefault(k, v)
        else:
            node[key] = remaining

    return node


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: normalize_openapi.py <in.json> <out.json>")
    with open(sys.argv[1], encoding="utf-8") as fh:
        spec = json.load(fh)
    spec = normalize(spec)
    spec["openapi"] = "3.0.3"
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(spec, fh, indent=1)
    print(f"normalized -> {sys.argv[2]}")


if __name__ == "__main__":
    main()
