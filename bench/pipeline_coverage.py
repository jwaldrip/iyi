#!/usr/bin/env python3
# Coverage of the typed pipeline against the hosted compiler's function list (SPEC 2.1, S3).
#
#   python3 bench/pipeline_coverage.py <hosted.ll> <port.names> <root>
#
# <hosted.ll> is the hosted compiler's output for the root (`./bin/iyi build --no-debug --emit llvm-ir -o <dir>/hosted
# <root>`): its `define` names. <port.names> is what the typed pipeline lowered clean, one distinct name per line (the
# tool writes it as `<output>.names` under --keep-going; the comparison is on sets).
# Prints one summary line and the first 20 missing names:
#
#   table: <root> hosted-functions=N lowered-clean-and-in-hosted=M missing=K extra=E
#   table: <root> missing: <name>
#
# missing = hosted functions the port has not lowered clean; extra = port functions the hosted compiler does not define.
# The hosted compiler prefixes a top-level def with its file path (`*/abs/prelude.iyi::__iyi_say`); the port emits
# `*__iyi_say`. The file part is dropped on the hosted side so the comparison is on the def, not on the checkout.
import re
import sys

DEFINE = re.compile(r'^define\b[^@]*@("(?:[^"\\]|\\.)*"|[^\s(]+)')
FILE_PREFIX = re.compile(r'^\*(?:/[^:]*\.iyi)::')


def normal(name):
    return FILE_PREFIX.sub('*', name)


def hosted_names(path):
    names = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.startswith("define"):
                continue
            m = DEFINE.match(line)
            if m:
                name = m.group(1)
                if name.startswith('"') and name.endswith('"'):
                    name = name[1:-1]
                names.add(normal(name))
    return names


def port_names(path):
    with open(path, encoding="utf-8") as f:
        return {line.rstrip("\n") for line in f if line.strip()}


def main(argv):
    if len(argv) != 4:
        print(__doc__)
        return 2
    hosted_path, port_path, root = argv[1], argv[2], argv[3]
    hosted = hosted_names(hosted_path)
    port = port_names(port_path)
    both = hosted & port
    missing = sorted(hosted - port)
    extra = port - hosted
    print(f"table: {root} hosted-functions={len(hosted)} lowered-clean-and-in-hosted={len(both)} "
          f"missing={len(missing)} extra={len(extra)}")
    for name in missing[:20]:
        print(f"table: {root} missing: {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
