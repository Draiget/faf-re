"""Check gpgnet-messages.schema.json and copy its message schemas into docs/GPGNET_MESSAGES.md.

The doc marks each schema block with
    <!-- schema: <name in $defs> -->
    ```json
    ...
    ```
    <!-- /schema -->
and this script rewrites the block from the schema file.

    python docs/gpgnet/sync_doc.py           # rewrite the doc
    python docs/gpgnet/sync_doc.py --check   # exit 1 if the doc is out of date or the schema is wrong

The checks need the `jsonschema` package; without it only the doc is synced.
"""

import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "gpgnet-messages.schema.json"
DOC_PATH = HERE.parent / "GPGNET_MESSAGES.md"
LINE_WIDTH = 110

BLOCK = re.compile(r"(<!-- schema: (?P<name>[^ ]+) -->\n)(?P<body>.*?)(<!-- /schema -->)", re.S)


def compact(node, indent=0):
    """JSON with small values kept on one line."""
    flat = json.dumps(node, ensure_ascii=False)
    if len(flat) + indent <= LINE_WIDTH or not isinstance(node, (dict, list)) or not node:
        return flat
    pad = " " * (indent + 2)
    if isinstance(node, dict):
        items = [f"{pad}{json.dumps(k)}: {compact(v, indent + 2)}" for k, v in node.items()]
        return "{\n" + ",\n".join(items) + "\n" + " " * indent + "}"
    items = [pad + compact(v, indent + 2) for v in node]
    return "[\n" + ",\n".join(items) + "\n" + " " * indent + "]"


def check_schema(schema):
    """Return a list of problems: the schema itself, and every example against its message."""
    try:
        import jsonschema
    except ImportError:
        print("jsonschema not installed: schema checks skipped")
        return []

    problems = []
    validator_cls = jsonschema.Draft202012Validator
    try:
        validator_cls.check_schema(schema)
    except jsonschema.SchemaError as e:
        return [f"schema is not valid JSON Schema 2020-12: {e.message}"]

    root = validator_cls(schema)
    payload = validator_cls({"$ref": "#/$defs/JsonStatsPayload", "$defs": schema["$defs"]})
    for name, node in schema["$defs"].items():
        for example in node.get("examples", []):
            one = validator_cls({"$ref": f"#/$defs/{name}", "$defs": schema["$defs"]})
            for err in one.iter_errors(example):
                problems.append(f"{name}: example {example} fails: {err.message}")
            if not root.is_valid(example):
                problems.append(f"{name}: example {example} matches no message or more than one")
            if name == "FromGame.JsonStats":
                for err in payload.iter_errors(json.loads(example["args"][0])):
                    problems.append(f"{name}: example payload fails: {err.message}")
    return problems


def main():
    check_only = "--check" in sys.argv[1:]
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    defs = schema["$defs"]
    problems = check_schema(schema)

    doc = DOC_PATH.read_text(encoding="utf-8")
    shown = set()

    def render(match):
        name = match.group("name")
        if name not in defs:
            problems.append(f"doc names {name}, which is not in the schema")
            return match.group(0)
        shown.add(name)
        return f"{match.group(1)}```json\n{compact(defs[name])}\n```\n{match.group(4)}"

    new_doc = BLOCK.sub(render, doc)

    messages = [ref["$ref"].split("/")[-1] for group in ("FromGame", "ToGame") for ref in defs[group]["oneOf"]]
    for name in messages:
        if name not in shown:
            problems.append(f"{name} has no schema block in the doc")

    if new_doc != doc:
        if check_only:
            problems.append(f"{DOC_PATH.name} is out of date: run python docs/gpgnet/sync_doc.py")
        else:
            DOC_PATH.write_text(new_doc, encoding="utf-8", newline="\n")
            print(f"updated {DOC_PATH.name}")

    for p in problems:
        print(p)
    print(f"{len(messages)} messages, {len(shown)} schema blocks, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
