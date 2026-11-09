#!/usr/bin/env python3
"""Importable observed-corpus compiler shim for matching, execution, and ledger proof."""

from __future__ import annotations

import dataclasses
import fcntl
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Mapping, Sequence
from typing import NoReturn


CONFIG_KEYS = frozenset(
    {
        "real",
        "census",
        "ledger",
        "nonce",
        "driver",
        "work_tmp",
        "scratch",
        "repo",
        "canonical_roots",
        "platform_tmp",
    }
)
HEADER_KEYS = frozenset({"v", "kind", "nonce", "driver", "attempt", "chain_id"})
ENV_SEEN_KEYS = (
    "IYI_PATH",
    "CRYSTAL_PATH",
    "IYI_CACHE_DIR",
    "IYI_OPTS",
    "CRYSTAL_OPTS",
)


@dataclasses.dataclass(frozen=True)
class OptionSpec:
    arity: int | tuple[int, int]
    build_only: bool = False


# Transcribed from create_compiler in src/compiler/iyi/command.cr:807-1138
# and its target and warning option helpers at command.cr:1474-1522.
OPTION_TABLE: dict[str, OptionSpec] = {
    "--cross-compile": OptionSpec(0, build_only=True),
    "-d": OptionSpec(0),
    "--debug": OptionSpec(0),
    "--no-debug": OptionSpec(0),
    "--frame-pointers": OptionSpec(1),
    "-D": OptionSpec(1),
    "--define": OptionSpec(1),
    "--emit": OptionSpec((0, 1)),
    "--x86-asm-syntax": OptionSpec(1),
    "-f": OptionSpec(1),
    "--format": OptionSpec(1),
    "--error-trace": OptionSpec(0),
    "-h": OptionSpec(0),
    "--help": OptionSpec(0),
    "--ll": OptionSpec(0),
    "--link-flags": OptionSpec(1),
    "--mcpu": OptionSpec(1),
    "--mattr": OptionSpec(1),
    "--mcmodel": OptionSpec(1),
    "--warnings": OptionSpec(1),
    "--error-on-warnings": OptionSpec(0),
    "--exclude-warnings": OptionSpec(1),
    "--no-color": OptionSpec(0),
    "--no-codegen": OptionSpec(0),
    "-o": OptionSpec(1),
    "--output": OptionSpec(1),
    "--prelude": OptionSpec(1),
    "--crystal": OptionSpec(0),
    "--iyi-keep": OptionSpec(1),
    "--emit-bind": OptionSpec(1),
    "--emit-iyimod": OptionSpec(1),
    "--use-iyimod": OptionSpec(1),
    "--release": OptionSpec(0),
    "-O": OptionSpec(1),
    "-s": OptionSpec(0),
    "--stats": OptionSpec(0),
    "-p": OptionSpec(0),
    "--progress": OptionSpec(0),
    "-t": OptionSpec(0),
    "--time": OptionSpec(0),
    "--single-module": OptionSpec(0),
    "--threads": OptionSpec(1),
    "--target": OptionSpec(1, build_only=True),
    "--verbose": OptionSpec(0),
    "--static": OptionSpec(0),
    "--force": OptionSpec(0, build_only=True),
    "--stale-key": OptionSpec(1, build_only=True),
    "--stale-accept": OptionSpec(1, build_only=True),
    "--stale-block": OptionSpec(1, build_only=True),
    "--stale-dump-elements": OptionSpec(1, build_only=True),
    "--stdin-filename": OptionSpec(1),
}

UNCHANGED_EXACT = frozenset({"--crystal", "--no-codegen", "--emit"})
PASSTHROUGH_EXACT = frozenset({"--emit-iyimod", "--use-iyimod"})


class ShimError(RuntimeError):
    """A closed refusal, not a proof-tool crash."""


class ConfigError(ShimError):
    pass


class InvocationError(ShimError):
    pass


@dataclasses.dataclass(frozen=True)
class Invocation:
    argv: tuple[str, ...]
    command_word: str
    command: str
    compiler_args: tuple[str, ...]
    run_args: tuple[str, ...]
    sources: tuple[str, ...]
    output: str | None
    has_separator: bool


@dataclasses.dataclass(frozen=True)
class CompilerEnvironment:
    roots: tuple[str, ...]
    cache_dir: str


@dataclasses.dataclass(frozen=True)
class Classification:
    mode: str
    canonical: bool
    first_noncanonical_root: str | None
    variant_ids: tuple[str, ...]
    variant_kind: str | None
    bindings: dict[str, dict[str, str]]
    status: str
    reason: str | None


@dataclasses.dataclass(frozen=True)
class ExecPlan:
    real: str
    argv: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class _ChildResult:
    rc: int
    stdout: bytes
    stderr: bytes
    interrupted: int | None


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while chunk := source.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def load_config(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as source:
            config = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigError(f"config unreadable: {error}") from error
    if not isinstance(config, dict):
        raise ConfigError("config is not an object")
    keys = frozenset(config)
    if keys != CONFIG_KEYS:
        missing = sorted(CONFIG_KEYS - keys)
        unknown = sorted(keys - CONFIG_KEYS)
        raise ConfigError(f"config keys differ: missing={missing}, unknown={unknown}")
    for key in CONFIG_KEYS - {"canonical_roots", "platform_tmp"}:
        if not isinstance(config[key], str):
            raise ConfigError(f"config {key} is not a string")
    platform_tmp = config["platform_tmp"]
    if platform_tmp is not None and not isinstance(platform_tmp, str):
        raise ConfigError("config platform_tmp is not a string or null")
    if isinstance(platform_tmp, str) and os.path.realpath(platform_tmp) != platform_tmp:
        raise ConfigError("config platform_tmp is not a realpath")
    roots = config["canonical_roots"]
    if not isinstance(roots, list) or any(not isinstance(root, str) for root in roots):
        raise ConfigError("config canonical_roots is not a string list")
    if re.fullmatch(r"[0-9a-f]{32}", config["nonce"]) is None:
        raise ConfigError("config nonce is not 32 lowercase hex characters")
    for key in ("real", "census", "work_tmp", "repo"):
        if os.path.realpath(config[key]) != config[key]:
            raise ConfigError(f"config {key} is not a realpath")
    if not os.path.isabs(config["ledger"]) or not os.path.isabs(config["scratch"]):
        raise ConfigError("config ledger and scratch must be absolute")
    normalized_roots = [os.path.realpath(root) for root in roots]
    if normalized_roots != roots:
        raise ConfigError("config canonical_roots contains a non-realpath")
    return config


def read_header(ledger_path: str, *, nonce: str | None = None, driver: str | None = None) -> dict:
    try:
        with open(ledger_path, "r", encoding="utf-8") as source:
            first = source.readline()
    except (OSError, UnicodeError) as error:
        raise ConfigError(f"ledger unavailable: {error}") from error
    if not first:
        raise ConfigError("ledger header is missing")
    try:
        header = json.loads(first)
    except json.JSONDecodeError as error:
        raise ConfigError(f"ledger header is invalid JSON: {error}") from error
    if not isinstance(header, dict) or frozenset(header) != HEADER_KEYS:
        raise ConfigError("ledger header shape is invalid")
    if header.get("v") != 1 or header.get("kind") != "header":
        raise ConfigError("ledger header version or kind is invalid")
    if not isinstance(header.get("attempt"), int) or isinstance(header.get("attempt"), bool):
        raise ConfigError("ledger header attempt is invalid")
    if not isinstance(header.get("chain_id"), str) or not header["chain_id"]:
        raise ConfigError("ledger header chain_id is invalid")
    if nonce is not None and header.get("nonce") != nonce:
        raise ConfigError("ledger header nonce does not match config")
    if driver is not None and header.get("driver") != driver:
        raise ConfigError("ledger header driver does not match config")
    return header


def _normalized_command(word: str) -> str:
    if word and "build".startswith(word):
        return "build"
    if word == "run":
        return "run"
    return word


def _arity_bounds(spec: OptionSpec) -> tuple[int, int]:
    if isinstance(spec.arity, tuple):
        return spec.arity
    return spec.arity, spec.arity


def _option(token: str) -> tuple[str, OptionSpec, str | None] | None:
    direct = OPTION_TABLE.get(token)
    if direct is not None:
        return token, direct, None
    if token.startswith("--") and "=" in token:
        name, value = token.split("=", 1)
        spec = OPTION_TABLE.get(name)
        if spec is None or _arity_bounds(spec)[1] != 1:
            return None
        return name, spec, value
    if token.startswith("-") and not token.startswith("--"):
        for name in ("-D", "-o", "-O", "-f"):
            if token.startswith(name) and token != name:
                spec = OPTION_TABLE[name]
                return name, spec, token[len(name) :]
    return None


def parse_invocation(argv: Sequence[str]) -> Invocation:
    received = tuple(str(token) for token in argv)
    if not received:
        return Invocation((), "", "", (), (), (), None, False)
    command_word = received[0]
    command = _normalized_command(command_word)
    if os.path.isfile(command_word) or command_word.endswith((".iyi", ".cr")):
        raise InvocationError(f"implicit file form is unsupported: {command_word}")
    if command not in ("build", "run"):
        return Invocation(received, command_word, command, received[1:], (), (), None, False)

    tail = list(received[1:])
    if "--" in tail:
        separator = tail.index("--")
        before = tail[:separator]
        run_args = tuple(tail[separator + 1 :])
        has_separator = True
    else:
        before = tail
        run_args = ()
        has_separator = False
    if command == "run" and "--sandbox" in before:
        raise InvocationError("run --sandbox is unsupported")

    sources: list[str] = []
    output: str | None = None
    index = 0
    while index < len(before):
        token = before[index]
        if token.startswith("-") and token != "-":
            matched = _option(token)
            if matched is None:
                raise InvocationError(f"unknown option: {token}")
            name, spec, attached = matched
            if (
                spec.build_only
                and command != "build"
                and name != "--cross-compile"
            ):
                raise InvocationError(f"build-only option on run: {name}")
            if name == "--stdin-filename":
                raise InvocationError("--stdin-filename is unsupported")
            minimum, maximum = _arity_bounds(spec)
            if maximum == 0:
                index += 1
                continue
            if attached is None:
                if minimum == 0 and (
                    index + 1 >= len(before)
                    or _option(before[index + 1]) is not None
                ):
                    value = ""
                    index += 1
                else:
                    if index + 1 >= len(before):
                        raise InvocationError(f"option requires a value: {name}")
                    value = before[index + 1]
                    index += 2
            else:
                value = attached
                index += 1
            if name in ("-o", "--output"):
                output = value
            continue
        sources.append(token)
        index += 1

    return Invocation(
        argv=received,
        command_word=command_word,
        command=command,
        compiler_args=tuple(before),
        run_args=run_args,
        sources=tuple(sources),
        output=output,
        has_separator=has_separator,
    )


def _tokenize_ambient_options() -> tuple[str, ...]:
    tokens: list[str] = []
    for name in ("IYI_OPTS", "CRYSTAL_OPTS"):
        value = os.environ.get(name)
        if value is None or value == "":
            continue
        try:
            tokens.extend(shlex.split(value, posix=True))
        except ValueError as error:
            raise InvocationError(f"cannot parse {name}: {error}") from error
    return tuple(tokens)

def _recognized_option_tokens(tokens: Sequence[str], *, command: str, allow_positionals: bool) -> tuple[str, ...]:
    recognized: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("-") or token == "-":
            if not allow_positionals:
                raise InvocationError("IYI_OPTS/CRYSTAL_OPTS may not contain positional arguments")
            index += 1
            continue
        if token == "--":
            raise InvocationError("IYI_OPTS/CRYSTAL_OPTS may not contain --")
        matched = _option(token)
        if matched is None:
            raise InvocationError(f"unknown option: {token}")
        name, spec, attached = matched
        if (
            spec.build_only
            and command != "build"
            and name != "--cross-compile"
        ):
            raise InvocationError(f"build-only option on run: {name}")
        if name == "--stdin-filename":
            raise InvocationError("--stdin-filename is unsupported")
        recognized.append(token)
        minimum, maximum = _arity_bounds(spec)
        if maximum == 1 and attached is None:
            if minimum == 0 and (
                index + 1 >= len(tokens)
                or _option(tokens[index + 1]) is not None
            ):
                index += 1
            else:
                if index + 1 >= len(tokens):
                    raise InvocationError(f"option requires a value: {name}")
                index += 2
        else:
            index += 1
    return tuple(recognized)



def compiler_env(real: str, cwd: str) -> CompilerEnvironment:
    try:
        completed = subprocess.run(
            [real, "env", "IYI_PATH", "IYI_CACHE_DIR"],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise InvocationError(f"compiler env failed: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise InvocationError(
            f"compiler env exited {completed.returncode}: {detail or 'no stderr'}"
        )
    lines = completed.stdout.decode("utf-8", errors="replace").splitlines()
    if len(lines) != 2:
        raise InvocationError(f"compiler env returned {len(lines)} lines, expected 2")
    path_value, cache_value = lines
    roots: list[str] = []
    for entry in path_value.split(os.pathsep):
        if entry == "":
            continue
        candidate = entry if os.path.isabs(entry) else os.path.join(cwd, entry)
        roots.append(os.path.realpath(candidate))
    cache_candidate = cache_value if os.path.isabs(cache_value) else os.path.join(cwd, cache_value)
    return CompilerEnvironment(tuple(roots), os.path.realpath(cache_candidate))


def _realpath_from_cwd(path: str, cwd: str) -> str:
    candidate = path if os.path.isabs(path) else os.path.join(cwd, path)
    return os.path.realpath(candidate)


def compute_out(invocation: Invocation, *, cwd: str, cache_dir: str, pid: int | None = None) -> str | None:
    if invocation.command not in ("build", "run"):
        return None
    if invocation.output is not None:
        return _realpath_from_cwd(invocation.output, cwd)
    source = invocation.sources[0] if invocation.sources else "a.iyi"
    stem = os.path.splitext(os.path.basename(source))[0] or "a"
    if invocation.command == "run":
        if not cache_dir:
            raise InvocationError("compiler env returned an empty IYI_CACHE_DIR")
        runner_pid = os.getpid() if pid is None else pid
        return os.path.realpath(
            os.path.join(cache_dir, f"iyi-run-{stem}-{runner_pid}.tmp")
        )
    return os.path.realpath(os.path.join(cwd, stem))


def _template_regex(template: str, *, variables: Mapping[str, object], bound: Mapping[str, str], work_tmp: str, repo: str, platform_tmp: str | None) -> tuple[re.Pattern[str], dict[str, str]]:
    parts: list[str] = []
    group_names: dict[str, str] = {}
    position = 0
    for placeholder in re.finditer(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template):
        parts.append(re.escape(template[position : placeholder.start()]))
        name = placeholder.group(1)
        if name == "REPO":
            parts.append(re.escape(repo))
        elif name == "WORK":
            if name in bound:
                parts.append(re.escape(bound[name]))
            elif name in group_names:
                parts.append(f"(?P={group_names[name]})")
            else:
                roots = [os.path.realpath(work_tmp)]
                if platform_tmp is not None:
                    roots.append(os.path.realpath(platform_tmp))
                root_body = "|".join(
                    re.escape(root) for root in dict.fromkeys(roots)
                )
                group_names[name] = "iyi_work"
                parts.append(
                    f"(?P<iyi_work>(?:{root_body}){re.escape(os.sep)}[^/]+)"
                )
        elif name in variables:
            if name in bound:
                parts.append(re.escape(bound[name]))
            elif name in group_names:
                parts.append(f"(?P={group_names[name]})")
            else:
                group_name = f"iyi_var_{len(group_names)}"
                group_names[name] = group_name
                declaration = variables[name]
                if not isinstance(declaration, dict):
                    raise ValueError(f"variable {name} declaration is not an object")
                values = declaration.get("values")
                pattern = declaration.get("pattern")
                if isinstance(values, list) and values and all(
                    isinstance(value, str) for value in values
                ):
                    body = "|".join(re.escape(value) for value in values)
                elif isinstance(pattern, str) and pattern:
                    body = pattern
                else:
                    raise ValueError(f"variable {name} has no values or pattern")
                parts.append(f"(?P<{group_name}>{body})")
        else:
            raise ValueError(f"unknown template placeholder {name}")
        position = placeholder.end()
    parts.append(re.escape(template[position:]))
    return re.compile("".join(parts)), group_names


def _match_template(template: object, actual: str, *, variables: Mapping[str, object], bindings: dict[str, str], work_tmp: str, repo: str, platform_tmp: str | None) -> bool:
    if not isinstance(template, str):
        return False
    try:
        expression, groups = _template_regex(
            template,
            variables=variables,
            bound=bindings,
            work_tmp=work_tmp,
            repo=repo,
            platform_tmp=platform_tmp,
        )
    except (ValueError, re.error):
        return False
    matched = expression.fullmatch(os.path.realpath(actual))
    if matched is None:
        return False
    for name, group_name in groups.items():
        bindings[name] = matched.group(group_name)
    return True


def match_variants(census: dict, command: str, first_root: str | None, sources: Sequence[str], output: str | None, work_tmp: str, repo: str, *, platform_tmp: str | None) -> tuple[str, list[str], str | None, dict[str, dict[str, str]]]:
    if first_root is None:
        return "unclassified", [], None, {}
    normalized_work = os.path.realpath(work_tmp)
    normalized_repo = os.path.realpath(repo)
    normalized_sources = [os.path.realpath(source) for source in sources]
    normalized_output = os.path.realpath(output) if output is not None else None
    matches: list[tuple[str, str, dict[str, str]]] = []
    for site in census.get("sites", []):
        if not isinstance(site, dict) or site.get("command") != command:
            continue
        for variant in site.get("variants", []):
            if not isinstance(variant, dict):
                continue
            variant_id = variant.get("id")
            kind = variant.get("kind")
            templates = variant.get("sources")
            variables = variant.get("vars", {})
            if (
                not isinstance(variant_id, str)
                or kind not in ("negative", "positive")
                or not isinstance(templates, list)
                or not isinstance(variables, dict)
                or len(templates) != len(normalized_sources)
            ):
                continue
            bindings: dict[str, str] = {}
            if not _match_template(
                variant.get("first_root"),
                os.path.realpath(first_root),
                variables=variables,
                bindings=bindings,
                work_tmp=normalized_work,
                repo=normalized_repo,
                platform_tmp=platform_tmp,
            ):
                continue
            matched_all = True
            for template, actual in zip(templates, normalized_sources):
                if not _match_template(
                    template,
                    actual,
                    variables=variables,
                    bindings=bindings,
                    work_tmp=normalized_work,
                    repo=normalized_repo,
                    platform_tmp=platform_tmp,
                ):
                    matched_all = False
                    break
            if not matched_all:
                continue
            output_template = variant.get("output")
            if output_template is not None:
                if normalized_output is None or not _match_template(
                    output_template,
                    normalized_output,
                    variables=variables,
                    bindings=bindings,
                    work_tmp=normalized_work,
                    repo=normalized_repo,
                    platform_tmp=platform_tmp,
                ):
                    continue
            declared_bindings = {
                name: bindings[name]
                for name in variables
                if name in bindings
            }
            matches.append((variant_id, kind, declared_bindings))
    if not matches:
        return "unclassified", [], None, {}
    kinds = {kind for _variant_id, kind, _bindings in matches}
    ids = [variant_id for variant_id, _kind, _bindings in matches]
    bindings_by_id = {
        variant_id: variant_bindings
        for variant_id, _kind, variant_bindings in matches
    }
    if len(kinds) != 1:
        return "ambiguous", ids, None, bindings_by_id
    return "matched", ids, next(iter(kinds)), bindings_by_id


def _has_unchanged_trigger(tokens: Sequence[str]) -> bool:
    for token in tokens:
        if token in UNCHANGED_EXACT:
            return True
        if token.startswith("--emit=") or token.startswith("--emit-bind"):
            return True
        if token.startswith("--cross-compile"):
            return True
    return False


def _has_passthrough_trigger(tokens: Sequence[str]) -> bool:
    return any(
        token in PASSTHROUGH_EXACT
        or token.startswith("--emit-iyimod=")
        or token.startswith("--use-iyimod=")
        for token in tokens
    )


def classify(census: dict, invocation: Invocation, roots: Sequence[str], canonical_roots: Sequence[str], sources: Sequence[str], output: str | None, work_tmp: str, repo: str, *, platform_tmp: str | None, ambient_tokens: Sequence[str] = ()) -> Classification:
    normalized_roots = tuple(os.path.realpath(root) for root in roots)
    canonical_set = {os.path.realpath(root) for root in canonical_roots}
    first_noncanonical = next(
        (root for root in normalized_roots if root not in canonical_set),
        None,
    )
    canonical = first_noncanonical is None
    if invocation.command not in ("build", "run"):
        return Classification(
            "unchanged", canonical, first_noncanonical, (), None, {}, "unchanged", None
        )
    trigger_tokens = (
        *_recognized_option_tokens(
            invocation.compiler_args,
            command=invocation.command,
            allow_positionals=True,
        ),
        *_recognized_option_tokens(
            ambient_tokens,
            command=invocation.command,
            allow_positionals=False,
        ),
    )
    if _has_unchanged_trigger(trigger_tokens):
        return Classification(
            "unchanged", canonical, first_noncanonical, (), None, {}, "unchanged", None
        )
    if _has_passthrough_trigger(trigger_tokens):
        return Classification(
            "passthrough", canonical, first_noncanonical, (), None, {}, "passthrough", None
        )
    if canonical:
        return Classification(
            "roundtrip", True, None, (), None, {}, "canonical", "canonical roots"
        )
    status, variant_ids, kind, bindings = match_variants(
        census,
        invocation.command,
        first_noncanonical,
        sources,
        output,
        work_tmp,
        repo,
        platform_tmp=platform_tmp,
    )
    if status != "matched":
        return Classification(
            "refused",
            False,
            first_noncanonical,
            tuple(variant_ids),
            kind,
            bindings,
            status,
            f"{status} variant match",
        )
    mode = "roundtrip" if kind == "positive" else "observed-negative"
    return Classification(
        mode,
        False,
        first_noncanonical,
        tuple(variant_ids),
        kind,
        bindings,
        status,
        f"matched {kind} variant",
    )


def _observe_definitions(tokens: Sequence[str]) -> int:
    count = 0
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-D" or token == "--define":
            if index + 1 < len(tokens) and tokens[index + 1] == "iyi_observe":
                count += 1
            index += 2
            continue
        if token == "-Diyi_observe" or token == "--define=iyi_observe":
            count += 1
        index += 1
    return count


def _with_observe(invocation: Invocation, *, ambient_tokens: Sequence[str] = ()) -> list[str]:
    tokens = list(invocation.argv)
    if _observe_definitions((*invocation.compiler_args, *ambient_tokens)) == 0:
        tokens.insert(1, "-Diyi_observe")
    return tokens


def build_exec_argv(invocation: Invocation, *, ambient_tokens: Sequence[str] = ()) -> list[str]:
    return _with_observe(invocation, ambient_tokens=ambient_tokens)


def build_producer_argv(invocation: Invocation, mods: str, output: str, *, ambient_tokens: Sequence[str] = ()) -> list[str]:
    tokens = [invocation.command_word]
    if _observe_definitions((*invocation.compiler_args, *ambient_tokens)) == 0:
        tokens.append("-Diyi_observe")
    tokens.extend(("--emit-iyimod", mods))
    tokens.extend(invocation.compiler_args)
    if invocation.command == "run" and invocation.output is None:
        tokens.extend(("-o", output))
    return tokens


def build_consumer_argv(invocation: Invocation, mods: str, output: str, *, ambient_tokens: Sequence[str] = ()) -> list[str]:
    tokens = [invocation.command_word]
    if _observe_definitions((*invocation.compiler_args, *ambient_tokens)) == 0:
        tokens.append("-Diyi_observe")
    tokens.extend(("--use-iyimod", mods))
    tokens.extend(invocation.compiler_args)
    if invocation.command == "run" and invocation.output is None:
        tokens.extend(("-o", output))
    return tokens


def write_record(ledger_path: str, record: Mapping[str, object]) -> None:
    encoded = (
        json.dumps(dict(record), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    descriptor = os.open(ledger_path, os.O_WRONLY | os.O_APPEND)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.write(descriptor, encoded)
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _source_paths(invocation: Invocation, cwd: str) -> tuple[str, ...]:
    return tuple(_realpath_from_cwd(source, cwd) for source in invocation.sources)


def _base_record(config: Mapping[str, object], invocation: Invocation, classification: Classification, roots: Sequence[str], sources: Sequence[str], output: str | None, *, inv: str, phase: str, reason: str | None = None) -> dict[str, object]:
    driver = str(config["driver"])
    own_source = os.path.realpath(
        os.path.join(str(config["repo"]), "bench", f"std_{driver}_exercise.iyi")
    )
    own = classification.canonical and list(sources) == [own_source]
    return {
        "v": 1,
        "kind": "record",
        "nonce": config["nonce"],
        "driver": driver,
        "inv": inv,
        "pid": os.getpid(),
        "t_ns": time.monotonic_ns(),
        "phase": phase,
        "mode": classification.mode,
        "cwd": os.getcwd(),
        "argv": list(invocation.argv),
        "env_seen": {key: os.environ.get(key) for key in ENV_SEEN_KEYS},
        "command": invocation.command,
        "roots": list(roots),
        "canonical": classification.canonical,
        "first_noncanonical_root": classification.first_noncanonical_root,
        "variant_ids": list(classification.variant_ids),
        "variant_kind": classification.variant_kind,
        "bindings": classification.bindings,
        "sources": list(sources),
        "out": output,
        "own": own,
        "reason": reason if reason is not None else classification.reason,
    }


def _minimal_refusal_classification(reason: str) -> Classification:
    return Classification(
        "refused", False, None, (), None, {}, "refused", reason
    )


def _print_refusal(reason: str) -> None:
    sys.stderr.write(f"observed-roundtrip-shim: REFUSED {reason}\n")
    sys.stderr.flush()


def _record_refusal(config: Mapping[str, object], invocation: Invocation, reason: str, *, inv: str, roots: Sequence[str] = (), sources: Sequence[str] = (), output: str | None = None, classification: Classification | None = None) -> int:
    refused = classification or _minimal_refusal_classification(reason)
    record = _base_record(
        config,
        invocation,
        refused,
        roots,
        sources,
        output,
        inv=inv,
        phase="refused",
        reason=reason,
    )
    record["exit"] = 125
    try:
        write_record(str(config["ledger"]), record)
    except OSError:
        pass
    _print_refusal(reason)
    return 125


def _run_build(argv: Sequence[str], *, capture: bool) -> _ChildResult:
    stdout = subprocess.PIPE if capture else None
    stderr = subprocess.PIPE if capture else None
    process = subprocess.Popen(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
    )
    interrupted: list[int | None] = [None]
    old_handlers: dict[int, object] = {}

    def forward(number: int, _frame: object) -> None:
        if interrupted[0] is None:
            interrupted[0] = number
        if process.poll() is None:
            process.send_signal(number)

    try:
        for candidate in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[candidate] = signal.getsignal(candidate)
            signal.signal(candidate, forward)
        out, err = process.communicate()
    finally:
        for candidate, handler in old_handlers.items():
            signal.signal(candidate, handler)
    return _ChildResult(
        process.returncode,
        out or b"",
        err or b"",
        interrupted[0],
    )


def _death_sentence(number: int) -> str:
    if number in {
        getattr(signal, "SIGSEGV", -2),
        getattr(signal, "SIGBUS", -3),
    }:
        return (
            "the program died of a memory fault. Outside `Pointer`, an iyi program "
            "cannot reach memory it does not own: if the program uses `Pointer`, "
            "that is the place to look, and on a target without iyi's runtime it "
            "can also be the stack running out. If neither, it is a bug in iyi's "
            "own runtime, and ours to fix: https://github.com/iyilang/iyi/issues"
        )
    if number == getattr(signal, "SIGINT", -1):
        description = "was interrupted"
    elif number == getattr(signal, "SIGILL", -4):
        description = "terminated because of an invalid instruction"
    elif number == getattr(signal, "SIGFPE", -5):
        description = "terminated because of a floating-point system exception"
    else:
        try:
            name = signal.Signals(number).name.removeprefix("SIG")
        except ValueError:
            name = str(number)
        description = f"received and didn't handle signal {name} ({number})"
    return f"the program was killed by signal {number} ({description})"


def _run_program(argv: Sequence[str]) -> tuple[int, int | None]:
    process = subprocess.Popen(list(argv))
    old_handlers: dict[int, object] = {
        signal.SIGINT: signal.getsignal(signal.SIGINT),
        signal.SIGTERM: signal.getsignal(signal.SIGTERM),
        signal.SIGHUP: signal.getsignal(signal.SIGHUP),
    }

    def forward(number: int, _frame: object) -> None:
        if process.poll() is None:
            process.send_signal(number)

    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, forward)
        signal.signal(signal.SIGHUP, forward)
        rc = process.wait()
    finally:
        for candidate, handler in old_handlers.items():
            signal.signal(candidate, handler)
    if rc >= 0:
        return rc, None
    number = -rc
    sys.stderr.write(f"iyi: {_death_sentence(number)}\n")
    sys.stderr.flush()
    return 1, number


def _write_bytes(stream: object, data: bytes) -> None:
    binary = getattr(stream, "buffer", None)
    if binary is not None:
        binary.write(data)
        binary.flush()
    else:
        stream.write(data.decode("utf-8", errors="replace"))
        stream.flush()


def _end_record(begin: Mapping[str, object], *, producer: Mapping[str, object], consumer: Mapping[str, object] | None, run: Mapping[str, object] | None, out_ref: str | None, out_ino: int | None, out_mtime_ns: int | None, atime_set_ns: int | None, e3_error: str | None, interrupted: bool, exit_code: int) -> dict[str, object]:
    record = dict(begin)
    record.update(
        {
            "t_ns": time.monotonic_ns(),
            "phase": "end",
            "producer": dict(producer),
            "consumer": dict(consumer) if consumer is not None else None,
            "run": dict(run) if run is not None else None,
            "out_ref": out_ref,
            "out_ino": out_ino,
            "out_mtime_ns": out_mtime_ns,
            "atime_set_ns": atime_set_ns,
            "e3_error": e3_error,
            "interrupted": interrupted,
            "exit": exit_code,
        }
    )
    return record


def run_roundtrip(config: Mapping[str, object], invocation: Invocation, classification: Classification, output: str, *, roots: Sequence[str], sources: Sequence[str], ambient_tokens: Sequence[str], inv: str) -> int:
    invocation_dir = os.path.join(str(config["scratch"]), inv)
    mods = os.path.join(invocation_dir, "mods")
    os.makedirs(mods, exist_ok=False)
    producer_args = [
        str(config["real"]),
        *build_producer_argv(
            invocation,
            mods,
            output,
            ambient_tokens=ambient_tokens,
        ),
    ]
    consumer_args = [
        str(config["real"]),
        *build_consumer_argv(
            invocation,
            mods,
            output,
            ambient_tokens=ambient_tokens,
        ),
    ]
    begin = _base_record(
        config,
        invocation,
        classification,
        roots,
        sources,
        output,
        inv=inv,
        phase="begin",
    )
    write_record(str(config["ledger"]), begin)

    producer_result = _run_build(producer_args, capture=True)
    mods_count = len(glob.glob(os.path.join(mods, "**", "*.iyimod"), recursive=True))
    producer = {
        "argv": producer_args,
        "rc": producer_result.rc,
        "mods_count": mods_count,
    }
    if producer_result.interrupted is not None or producer_result.rc != 0:
        interrupted = producer_result.interrupted is not None
        exit_code = (
            128 + producer_result.interrupted
            if producer_result.interrupted is not None
            else producer_result.rc
        )
        if not interrupted:
            _write_bytes(sys.stdout, producer_result.stdout)
            _write_bytes(sys.stderr, producer_result.stderr)
        shutil.rmtree(invocation_dir, ignore_errors=True)
        end = _end_record(
            begin,
            producer=producer,
            consumer=None,
            run=None,
            out_ref=None,
            out_ino=None,
            out_mtime_ns=None,
            atime_set_ns=None,
            e3_error=None,
            interrupted=interrupted,
            exit_code=exit_code,
        )
        write_record(str(config["ledger"]), end)
        return exit_code

    if os.path.lexists(output):
        os.unlink(output)
    consumer_result = _run_build(consumer_args, capture=False)
    out_written = os.path.isfile(output)
    out_sha = sha256_file(output) if out_written else None
    consumer = {
        "argv": consumer_args,
        "rc": consumer_result.rc,
        "out_written": out_written,
        "out_sha256": out_sha,
    }

    out_ref: str | None = None
    out_ino: int | None = None
    out_mtime_ns: int | None = None
    atime_set_ns: int | None = None
    e3_error: str | None = None
    own_or_positive_build = invocation.command == "build" and (
        bool(begin["own"]) or classification.variant_kind == "positive"
    )
    if consumer_result.rc == 0 and out_written and own_or_positive_build:
        candidate_ref = os.path.join(invocation_dir, "out.ref")
        try:
            os.link(output, candidate_ref)
            stat = os.stat(output)
            out_ref = candidate_ref
            out_ino = stat.st_ino
            out_mtime_ns = stat.st_mtime_ns
            atime_set_ns = max(0, out_mtime_ns - 1_000_000_000)
            os.utime(output, ns=(atime_set_ns, out_mtime_ns))
        except OSError as error:
            try:
                os.unlink(candidate_ref)
            except OSError:
                pass
            out_ref = None
            out_ino = None
            out_mtime_ns = None
            atime_set_ns = None
            e3_error = f"{type(error).__name__}: {error}"

    run_record: dict[str, object] | None = None
    run_exit: int | None = None
    temporary_run_output = invocation.command == "run" and invocation.output is None
    if (
        temporary_run_output
        and consumer_result.rc == 0
        and consumer_result.interrupted is None
        and out_written
    ):
        run_argv = [output, *invocation.run_args]
        run_exit, run_signal = _run_program(run_argv)
        os.unlink(output)
        run_record = {
            "argv": run_argv,
            "rc": run_exit,
            "signal": run_signal,
        }

    interrupted = consumer_result.interrupted is not None
    if interrupted:
        exit_code = 128 + int(consumer_result.interrupted)
    elif consumer_result.rc != 0:
        exit_code = consumer_result.rc
    elif run_exit is not None:
        exit_code = run_exit
    else:
        exit_code = consumer_result.rc

    divergence = producer_result.rc == 0 and consumer_result.rc != 0
    if not divergence:
        shutil.rmtree(mods, ignore_errors=True)
    end = _end_record(
        begin,
        producer=producer,
        consumer=consumer,
        run=run_record,
        out_ref=out_ref,
        out_ino=out_ino,
        out_mtime_ns=out_mtime_ns,
        atime_set_ns=atime_set_ns,
        e3_error=e3_error,
        interrupted=interrupted,
        exit_code=exit_code,
    )
    write_record(str(config["ledger"]), end)
    return exit_code


def _load_census(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as source:
            census = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InvocationError(f"census unreadable: {error}") from error
    if not isinstance(census, dict):
        raise InvocationError("census is not an object")
    return census


def run_shim(config_path: str, argv: Sequence[str]) -> int | ExecPlan:
    try:
        config = load_config(config_path)
    except ConfigError as error:
        _print_refusal(str(error))
        return 125
    try:
        read_header(
            config["ledger"],
            nonce=config["nonce"],
            driver=config["driver"],
        )
    except ConfigError as error:
        _print_refusal(str(error))
        return 125

    received = tuple(str(token) for token in argv)
    inv = uuid.uuid4().hex
    try:
        invocation = parse_invocation(received)
    except InvocationError as error:
        fallback = Invocation(
            received,
            received[0] if received else "",
            _normalized_command(received[0]) if received else "",
            (),
            (),
            (),
            None,
            False,
        )
        return _record_refusal(config, fallback, str(error), inv=inv)

    try:
        ambient_tokens = _tokenize_ambient_options()
        cwd = os.getcwd()
        environment = compiler_env(config["real"], cwd)
        if invocation.command in ("build", "run"):
            sources = _source_paths(invocation, cwd)
            output = compute_out(
                invocation,
                cwd=cwd,
                cache_dir=environment.cache_dir,
                pid=os.getpid(),
            )
            census = _load_census(config["census"])
        else:
            sources = ()
            output = None
            census = {}
        classification = classify(
            census,
            invocation,
            environment.roots,
            config["canonical_roots"],
            sources,
            output,
            config["work_tmp"],
            config["repo"],
            platform_tmp=config["platform_tmp"],
            ambient_tokens=ambient_tokens,
        )
    except InvocationError as error:
        return _record_refusal(config, invocation, str(error), inv=inv)

    if classification.mode == "refused":
        return _record_refusal(
            config,
            invocation,
            classification.reason or "unclassified invocation",
            inv=inv,
            roots=environment.roots,
            sources=sources,
            output=output,
            classification=classification,
        )

    if classification.mode in ("unchanged", "passthrough", "observed-negative"):
        record = _base_record(
            config,
            invocation,
            classification,
            environment.roots,
            sources,
            output,
            inv=inv,
            phase="exec",
        )
        record["exit"] = 0
        write_record(config["ledger"], record)
        exec_argv = (
            list(invocation.argv)
            if classification.mode == "unchanged"
            else build_exec_argv(invocation, ambient_tokens=ambient_tokens)
        )
        return ExecPlan(config["real"], tuple(exec_argv))

    return run_roundtrip(
        config,
        invocation,
        classification,
        output,
        roots=environment.roots,
        sources=sources,
        ambient_tokens=ambient_tokens,
        inv=inv,
    )


def _exec_real(plan: ExecPlan) -> NoReturn:
    os.execv(plan.real, [plan.real, *plan.argv])


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) < 2 or arguments[0] != "--config":
        _print_refusal("usage: roundtrip_shim.py --config PATH -- ARGS...")
        return 125
    config_path = arguments[1]
    compiler_argv = arguments[2:]
    if compiler_argv and compiler_argv[0] == "--":
        compiler_argv = compiler_argv[1:]
    outcome = run_shim(config_path, compiler_argv)
    if isinstance(outcome, ExecPlan):
        _exec_real(outcome)
    return outcome


if __name__ == "__main__":
    raise SystemExit(main())
