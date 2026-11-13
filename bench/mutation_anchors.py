#!/usr/bin/env python3
"""Check supported mutation proof anchors without running their drivers.

    python3 bench/mutation_anchors.py            # check
    python3 bench/mutation_anchors.py --list     # print every anchor it found

A failure proof works by breaking the library and requiring the exercise to
notice. When the library is rewritten underneath it, the patch stops matching,
and a patch that matches nothing breaks nothing: the exercise passes, and the
proof reads as a pass while proving nothing at all. The drivers each catch this
at run time with `cmp -s`, but only for the platform and the exercise that ran,
and only after the minutes it takes to build and run them. This reads the
anchors directly, in a second, for all of them.

It checks two things per anchor:

  1. The patch changes its target file: a sed or awk program under this
     platform's own tool, a Python replace expression evaluated over the
     file's text, or a literal the driver replaces found in the file. That is
     the rot the drivers catch late.
  2. The pattern avoids the BRE escapes GNU and BSD sed disagree about. `\\?`,
     `\\+` and `\\|` are quantifiers and alternation to GNU and literal
     characters to BSD, so a pattern using one matches on the machine it was
     written on and silently matches nothing on the other. Both proofs lost to
     this in September 2026 were written and verified on macOS and matched
     nothing in Linux CI.

Anchors are found by reading each driver's `prove_fails`-style calls rather
than by running them, so a driver that needs a network, a container or another
architecture is still checked here. Shared `prove_mutation` calls are checked
by bench/lib/mutation.sh when their gate runs; this static checker does not
expand their shell variables or cover those calls.
"""

import glob
import os
import re
import shlex
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The escapes whose meaning changes between GNU and BSD sed, and what to write
# instead. A bracket expression means the same thing to both.
UNPORTABLE = {
    r"\?": "[?]",
    r"\+": "[+]",
    r"\|": "[|]",
}

# Drivers name their targets by basename and resolve them against their own
# library root, so the check does the same rather than parsing shell variables.
SEARCH_ROOTS = ("src/std", "src/iyi", "src/compiler", "bench", "samples/iyi")


def driver_calls(text):
    """Yield the argument list of every proof call in one driver."""
    # Join continuations first: these calls are written across several lines.
    joined = re.sub(r"\\\n\s*", " ", text)
    for line in joined.splitlines():
        stripped = line.strip()
        if not re.match(r"^prove_fail\w*\s+\S", stripped):
            continue
        if stripped.endswith("() {"):
            continue
        try:
            yield shlex.split(stripped)
        except ValueError:
            # An unbalanced quote is the shell's problem to report, not ours.
            continue


def resolve(name):
    for root in SEARCH_ROOTS:
        candidate = os.path.join(REPO, root, name)
        if os.path.isfile(candidate):
            return candidate
    matches = glob.glob(os.path.join(REPO, "src", "**", name), recursive=True)
    return matches[0] if matches else None


# One sed address, and an address or a range of them, as the drivers write
# them: a line number, `$`, or a /pattern/.
ADDRESS = r"(?:\d+|\$|/(?:[^/\\]|\\.)*/)"
RANGE = ADDRESS + r"(?:,(?:\+?\d+|" + ADDRESS + r"))?"


def scripts_in(args):
    """The patch programs in one call.

    The drivers write these shapes, and each appears somewhere different in
    the argument list, so every argument is examined rather than a position
    trusted:

        s/a/b/                        a plain substitution
        1,100s/a/b/                   one addressed to a line range
        /from/{n;s/a/b/;}             one addressed to a context, a line on
        /a/d   /a/,/b/{/c/d;}        an addressed delete, bare or in a block
        /a/,/b/c text   /a/i text     an addressed change or insert
        { if ($0 ~ /a/) ... print }   an awk program rewriting a whole line
        /a/ { ... } { ... print }     an awk program that starts at a pattern
        src.replace('a', 'b')         a Python expression over the file's text

    A literal the driver replaces (`prove_fails label dir phrase OLD NEW`) is
    not found here: nothing in the text of an argument says it is one. The
    function that takes it says so, and `driver_roots` reads that.
    """
    found = []
    for arg in args:
        text = arg.lstrip()
        awk_text = "$0" in text or "sub(" in text
        if awk_text and (
            text.startswith("{")
            or re.match(r"^/(?:[^/\\]|\\.)*/\s*(?:&&[^{]*)?\{", text)
        ):
            found.append(("awk", arg))
        elif re.match(
            r"^(?:\d+(?:,(?:\+?\d+))?"
            r"|/(?:[^/\\]|\\.)*/(?:,(?:\+?\d+|/(?:[^/\\]|\\.)*/))?)?"
            r"\{?\s*(?:\w+;\s*)*s[/|,]",
            text,
        ):
            found.append(("sed", arg))
        elif re.match(r"^" + RANGE + r"\s*(?:\{|[dcia](?:$|[\s;}\\]))", text):
            found.append(("sed", arg))
        elif re.match(r"^[A-Za-z_]\w*\.replace\(", text):
            found.append(("python", arg))
    return found


# A library file as a patch command names it: under `$REPO`, under the
# environment's REPO inside a Python f-string, or relative to the repository
# in a quoted Python path.
LIBRARY_FILE = (
    r"(?:\$REPO/|\{os\.environ\['REPO'\]\}/|(?<=[\"']))"
    r"(src/[\w/]+?)/(?:([\w.$]*?[\w.]+\.iyi)|[.])"
)


def function_paths(body):
    """The library roots one shell function names, and the file it patches."""
    roots, named = [], None
    for path in re.finditer(LIBRARY_FILE, body):
        if path.group(1) not in roots:
            roots.append(path.group(1))
    # The file the patch command reads, not the first path in the body:
    # a function that copies one library before patching another names
    # both, and only the patched one is what the anchors are about.
    for line in body.splitlines():
        reads = re.search(r"^\s*(sed|awk)\b", line) or re.search(
            r"read_text\(|\bopen\(", line
        )
        if not reads:
            continue
        found = re.search(LIBRARY_FILE, line)
        if found and found.group(2) and "$" not in found.group(2):
            named = found.group(2)
            break
        if found and re.match(r"^\s*awk\b", line) and "src/iyi" in roots:
            named = "prelude.iyi"
            break
    if named is None:
        # `local file="${5:-prelude.iyi}"`, or `${5:-std/set.iyi}`: the driver
        # states its own default in the shell rather than in the path it
        # patches.
        stated = re.search(r"\$\{\d+:-([\w./]+\.iyi)\}", body)
        if stated:
            named = stated.group(1)
    if named is None:
        # A Python patch that edits the copy in place names the copy:
        # `path = '$WORK/$dir/std/eiy.iyi'`.
        copy = re.search(r"^\s*path\s*=\s*['\"]\$WORK/[^'\"]*?/(\w+\.iyi)['\"]", body, re.M)
        if copy:
            named = copy.group(1)
    return roots, named


def literal_positions(body):
    """Where a proof function takes the literal it replaces, and its replacement.

    `local label="$1" dir="$2" phrase="$3" old="$4" new="$5"`, in a function
    whose Python replaces `old` in the file's text: the call's fourth and
    fifth arguments are the anchor. None when the function patches some other
    way.
    """
    if not re.search(r"\.replace\(\s*old\b", body):
        return None
    old = re.search(r"\bold\w*=\"\$\{?(\d+)", body)
    new = re.search(r"\bnew\w*=\"\$\{?(\d+)", body)
    if not old or not new:
        return None
    return int(old.group(1)), int(new.group(1))


def driver_roots(text):
    """Per proof function: the library paths, the default file, the literal.

    A driver patches either the prelude in `src/iyi` or a module in `src/std`,
    and names are shared across them (`io.iyi`, `float.iyi`), so resolving by
    basename alone picks the wrong file and reports a live anchor as dead.
    A driver may also define one proof function per file it patches, as the
    capsule driver does for `capsule.iyi` and `webtransport.iyi`, so the
    default is keyed by the function the call actually uses rather than taken
    from whichever definition happens to come first. A proof function that
    hands the patching to a helper (`patch_prelude "$dir" "$script"`) is read
    through the helper.
    """
    # A function ends at the brace that closes it, which sits at the indent
    # its name does, on a line of its own. One written on a single line
    # (`step() { echo "== $1"; }`), or defined inside an `if`, must not run on
    # to the next such brace and take the proof function with it.
    functions = {
        found.group(2): found.group(3)
        for found in re.finditer(
            r"^([ \t]*)(\w+)\(\)[ \t]*\{[ \t]*(?:#[^\n]*)?\n(.*?)\n\1\}",
            text,
            re.S | re.M,
        )
    }
    table = {}
    for name, body in functions.items():
        if not name.startswith("prove_fail"):
            continue
        roots, named = function_paths(body)
        if named is None:
            for helper, helper_body in functions.items():
                if helper == name or not re.search(
                    r"^\s*" + re.escape(helper) + r"\b", body, re.M
                ):
                    continue
                helper_roots, helper_named = function_paths(helper_body)
                roots = roots + [r for r in helper_roots if r not in roots]
                named = named or helper_named
        table[name] = (roots, named, literal_positions(body))
    return table


def resolve(name, roots):
    # `iyi/set.iyi`: a name that carries its library is that library's file.
    if "/" in name:
        candidate = os.path.join(REPO, "src", name)
        if os.path.isfile(candidate):
            return candidate
        name = os.path.basename(name)
    for root in list(roots) + list(SEARCH_ROOTS):
        candidate = os.path.join(REPO, root, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def anchors():
    """Every (driver, target, path, kind, script) this repository asserts.

    A call this cannot read is yielded too, with no script, because a checker
    that quietly skips what it does not understand reports a clean run over
    the anchors it happened to parse. That is the same failure as a patch that
    matches nothing, one level up.
    """
    for driver in sorted(glob.glob(os.path.join(REPO, "bench", "*.sh"))):
        text = open(driver, errors="ignore").read()
        table = driver_roots(text)
        for args in driver_calls(text):
            roots, fallback, literal = table.get(args[0], ([], None, None))
            name = next((a for a in args if a.endswith(".iyi")), None) or fallback
            if name is None:
                # Some drivers take the module by bare name, as `channel`, and
                # add the extension themselves.
                name = next(
                    (
                        a + ".iyi"
                        for a in args
                        if re.fullmatch(r"[a-z][a-z0-9_]*", a)
                        and resolve(a + ".iyi", roots)
                    ),
                    None,
                )
            if literal and len(args) > max(literal):
                found = [("literal", (args[literal[0]], args[literal[1]]))]
            else:
                found = scripts_in(args)
            if not found or name is None:
                yield os.path.relpath(driver, REPO), name, None, None, None
                continue
            path = resolve(name, roots)
            for kind, script in found:
                yield os.path.relpath(driver, REPO), name, path, kind, script


def address_only(script):
    """A change or an insert, as the delete of the lines it is addressed to.

    `/a/,/b/c text` and `/a/i text` are written across lines in the drivers,
    and BSD sed refuses them on one. What is checked is that the address still
    finds its lines, and a delete of those lines changes the file exactly when
    it does.
    """
    addressed = re.match(r"^(" + RANGE + r")\s*[cia](?:$|[\s\\])", script)
    return addressed.group(1) + "d" if addressed else script


def patches(path, kind, script):
    """True when this patch changes the file, using the real tool."""
    original = open(path, "rb").read()
    if kind == "literal":
        old, new = script
        return old != new and old.encode() in original
    if kind == "python":
        # The driver runs this same expression with python3, the file's text
        # bound to the name it starts with (`src`, `content`).
        text = original.decode(errors="surrogateescape")
        name = re.match(r"^\s*([A-Za-z_]\w*)\.", script).group(1)
        try:
            broken = eval(script, {"__builtins__": {}}, {name: text})
        except Exception:
            return None
        return broken != text
    argv = ["sed", "-e", address_only(script)] if kind == "sed" else ["awk", script]
    result = subprocess.run(argv, input=original, capture_output=True)
    if result.returncode != 0 and kind == "sed":
        # BSD sed wants a `;` before the brace that closes a block and GNU sed
        # does not mind one. A proof that only runs where sed is GNU, as the
        # Windows lock-race proofs do, is still read on a Mac this way.
        closed = re.sub(r"([dDgGhHnNpPx])\s*\}", r"\1;}", argv[2])
        result = subprocess.run(["sed", "-e", closed], input=original, capture_output=True)
    if result.returncode != 0:
        return None
    return result.stdout != original


def main():
    listing = "--list" in sys.argv
    checked = failures = 0

    for driver, target, path, kind, script in anchors():
        if script is None:
            print(f"UNREADABLE  {driver}")
            print(
                "  A proof call here names no patch program this checker can "
                "read, so nothing about it is being checked. Teach "
                "bench/mutation_anchors.py its shape rather than leaving it "
                "outside the count."
            )
            failures += 1
            continue

        checked += 1
        if listing:
            print(f"{driver}  {target}  {kind}  {script}")

        unportable = next((b for b in UNPORTABLE if kind == "sed" and b in script), None)
        if unportable:
            print(f"UNPORTABLE  {driver}")
            print(f"  {script}")
            print(
                f"  `{unportable}` means one thing to GNU sed and another to BSD "
                f"sed, so this matches on one platform and nothing on the other. "
                f"Write `{UNPORTABLE[unportable]}`."
            )
            failures += 1
            continue

        if path is None:
            print(f"MISSING     {driver}: no file named {target} under src/")
            failures += 1
            continue

        changed = patches(path, kind, script)
        if changed is None:
            print(f"REJECTED    {driver}: {kind} would not accept {script}")
            failures += 1
        elif not changed:
            print(f"MATCHES NOTHING  {driver}")
            print(f"  {script}")
            print(f"  against {os.path.relpath(path, REPO)}")
            print(
                "  The line this proof patches is gone, so the proof breaks "
                "nothing and the exercise passes without testing anything. "
                "Point it at the code that answers this question now."
            )
            failures += 1

    if failures:
        print()
        print(f"{failures} mutation anchors do not patch what they name.")
        return 1

    print(f"all {checked} supported prove_fails-style mutation anchors still patch the code they name")
    print("shared prove_mutation calls require their gate's runtime check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
