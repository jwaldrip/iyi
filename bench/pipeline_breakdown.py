#!/usr/bin/env python3
# The missing hosted names of one root, under the frontier's status line. Owner rules are pipeline_frontier.py's
# (the slice word the tool writes, typed_owner in lower/program.iyi, and the structural causes), so both tools agree.
#
#   python3 bench/pipeline_breakdown.py <hosted.ll> <port.names> <port.refusals> <root>
#
# Prints the frontier's first line (each missing name is refused, name-differs or not-reached), then the missing
# names by name shape and by owner, three examples each. A count under "by name shape" describes the hosted name's
# form only: it is not a naming defect in the port.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_frontier as pf  # noqa: E402


def main(argv):
    if len(argv) != 5:
        print(__doc__)
        return 2
    hosted_ll, names_path, refusals_path, root = argv[1:5]
    dset, _graph = pf.hosted_defines(hosted_ll)
    clean = dset & pf.port_names(names_path)
    by_label, reached, _full = pf.load_refusals(refusals_path)
    status = pf.statuses(dset, clean, by_label, reached)
    print(pf.status_line(root, dset, clean, status))
    pf.breakdown(root, dset, pf.port_names(names_path), by_label, reached)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
