# Reporting a Vulnerability

This is a pre-release fork of [Crystal](https://github.com/crystal-lang/crystal)
and it has no users to protect yet. It is not built for production and the
README says so.

**If the issue is in Crystal**, which is most of this code, report it to
Crystal: <security@manas.tech>. That is their mailbox and their process, and it
reaches everybody the bug actually affects.

**If the issue is in what this fork added** — the `.iyimod` artifact reader, the
import path, the rules in [SPEC.md](SPEC.md) — open a private security advisory
on this repository, or an ordinary issue if it is not sensitive. A malformed or
hostile `.iyimod` is the interesting case: the reader is the one place here that
parses something a program did not write itself.
