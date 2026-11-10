#!/usr/bin/env python3
"""
Compare two test outputs for semantic backtrace equivalence.

Usage:
    python3 bench/frames_equivalent.py [--across-optimisation] [--require-frames] OUT_A OUT_B
    python3 bench/frames_equivalent.py --strict-provenance --source-manifest SOURCE_JSON \\
        --artifact-manifest ARTIFACT_JSON --source-executable SOURCE_EXE \\
        --artifact-executable ARTIFACT_EXE [--require-frames] OUT_A OUT_B
    python3 bench/frames_equivalent.py --mutant KIND OUT

Tested by:
    python3 bench/test_frames_equivalent.py

Exit codes:
    0: Equivalent
    1: Not equivalent (first violation printed)
    2: Usage error or unreadable input
"""

import base64
import hashlib
import json
import os
import re
import struct
import sys

FRAME_RE = re.compile(rb'^(\d+) +(\S+) +0x[0-9a-fA-F]{16} (.*) \+ \d+$')
DARWIN_FRAME_RE = FRAME_RE
LINUX_FRAME_RE = re.compile(rb'^(\d+) +(\S+) at (.+):(\d+):(\d+)$')

def proc_location(sym: bytes):
    """Return the path and line spans of a current proc linkage name."""
    start = re.match(rb'^~proc\d*Proc\(', sym)
    if not start:
        return None
    depth = 1
    quote = None
    escaped = False
    for i in range(start.end(), len(sym)):
        c = sym[i]
        if c == ord('^'):
            return None
        if quote is not None:
            if escaped:
                escaped = False
            elif c == ord('\\'):
                escaped = True
            elif c == quote:
                quote = None
        elif c in (ord('"'), ord("'")):
            quote = c
        elif c == ord('('):
            depth += 1
        elif c == ord(')'):
            depth -= 1
            if depth == 0:
                if sym[i + 1:i + 2] != b'^':
                    return None
                location = re.fullmatch(rb'([^^]+):(\d+)', sym[i + 2:])
                if not location:
                    return None
                path_start = i + 2
                return (path_start, path_start + len(location.group(1)),
                        path_start + location.start(2), path_start + location.end(2))
    return None


def canonical_function(sym: bytes) -> bytes:
    location = proc_location(sym)
    if location:
        start, end, _, _ = location
        path = sym[start:end]
        canonical = canonical_file(path)
        if canonical != path:
            # NUL cannot occur in a linkage name and prevents a literal path
            # already named std/X from colliding with this equivalence class.
            return sym[:start] + b'\0' + canonical + sym[end:]
        return sym
    # Older proc symbols use @ as their location separator.
    legacy = re.fullmatch(rb'(~proc\d*@)([^@:]+):(\d+)', sym)
    if legacy:
        path = legacy.group(2)
        canonical = canonical_file(path)
        if canonical != path:
            return legacy.group(1) + b'\0' + canonical + b':' + legacy.group(3)
    return sym

def canonical_file(path: bytes) -> bytes:
    # Only paths beneath the std tree correspond; reject traversal and empty
    # components rather than equating a different file with a std module.
    match = re.fullmatch(rb'(?:.*?[/\\])?(?:src/std/(.+)\.iyi|mods/std/(.+)\.iyimod)', path)
    if match:
        module = match.group(1) or match.group(2)
        if all(part not in (b'', b'.', b'..') for part in re.split(rb'[/\\]', module)):
            return b'std/' + module
    return path


def parse_frame(line: bytes):
    s = line.rstrip(b'\r\n')
    m_darwin = FRAME_RE.match(s)
    if m_darwin:
        return (
            'darwin',
            m_darwin.group(1),
            m_darwin.group(2),
            canonical_function(m_darwin.group(3)),
        )
    m_linux = LINUX_FRAME_RE.match(s)
    if m_linux:
        return (
            'linux',
            m_linux.group(1),
            canonical_function(m_linux.group(2)),
            canonical_file(m_linux.group(3)),
            m_linux.group(4),
            m_linux.group(5),
        )
    return None


def is_frame(line: bytes) -> bool:
    return parse_frame(line) is not None

def is_named_function(fn: bytes) -> bool:
    if fn.startswith(b'[0x') and fn.endswith(b']'):
        return False
    if fn == b'0x0' or (fn.startswith(b'0x') and all(c in b'0123456789abcdefABCDEFx' for c in fn)):
        return False
    return True


def fields(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        raise ValueError("invalid provenance fields")
    return value


def text(value):
    if not isinstance(value, str) or not value:
        raise ValueError("invalid provenance text")
    try: value.encode("utf-8")
    except UnicodeError as exc: raise ValueError("invalid provenance UTF-8") from exc


def number(value):
    if type(value) is not int or not 0 <= value <= 0x7fffffff:
        raise ValueError("invalid provenance integer")


NAME_CONTEXTS = frozenset("method_name definition_name macro_name local_reference instance_variable class_variable parameter path_segment type_parameter where_variable named_entry enum_member special_global regex_match_index type_self module_segment".split())
PRODUCERS = frozenset("ConstructedAst EmptyTupleProjection EmptyNamedTupleProjection MacroTemplate MacroId MacroVar MacroVerbatim YieldWrapper SemanticPrinter StructuredSyntax ArtifactSemanticRenderer".split())
TOKEN_KINDS = frozenset(("EOF SPACE NEWLINE IDENT CONST INSTANCE_VAR CLASS_VAR CHAR STRING SYMBOL NUMBER _ COMMENT "
    "DELIMITER_START DELIMITER_END STRING_ARRAY_START INTERPOLATION_START SYMBOL_ARRAY_START STRING_ARRAY_END "
    "GLOBAL GLOBAL_MATCH_DATA_INDEX __DIR__ __END_LINE__ __FILE__ __LINE__ MACRO_LITERAL MACRO_EXPRESSION_START "
    "MACRO_CONTROL_START MACRO_VAR MACRO_END").split()) | frozenset(
    "! != !~ $? $~ % %= %} & && &&= &* &** &*= &+ &+= &- &-= &= ( ) * ** **= *= + += , - -= -> . .. ... / // //= /= : :: ; < << <<= <= <=> = == === => =~ > >= >> >>= ? @[ [ [] []= []? ] ^ ^= ` { {% {{ | |= || ||= } ~".split())


def guard(value, prefix=""):
    if not isinstance(value, str) or not re.fullmatch(prefix + r"[0-9a-f]{64}", value):
        raise ValueError("invalid input guard")


def token_fields(value):
    if value["lexical_mode"] not in ("Crystal", "Iyi") or value["token_kind"] not in TOKEN_KINDS:
        raise ValueError("invalid token classification")

NAME_OPERATORS = frozenset("! != !~ % & &* &** &+ &- * ** + - / // < << <= <=> = == === =~ > >= >> [] []= []? ^ ` | ~".split())
CONTEXT_KINDS = {
    "method_name": frozenset(("IDENT", "CONST")) | NAME_OPERATORS,
    "definition_name": frozenset(("IDENT",)) | (NAME_OPERATORS - {"!"}),
    "macro_name": frozenset(("IDENT", "CONST")) | (NAME_OPERATORS - {"!"}),
    "local_reference": frozenset(("IDENT",)),
    "instance_variable": frozenset(("INSTANCE_VAR",)),
    "class_variable": frozenset(("CLASS_VAR",)),
    "parameter": frozenset(("IDENT", "INSTANCE_VAR", "CLASS_VAR")),
    "path_segment": frozenset(("CONST",)),
    "type_parameter": frozenset(("CONST",)),
    "where_variable": frozenset(("CONST",)),
    "type_self": frozenset(("IDENT",)),
    "module_segment": frozenset(("IDENT",)),
    "named_entry": frozenset(("IDENT", "CONST")),
    "enum_member": frozenset(("CONST",)),
    "special_global": frozenset(("$~", "$?")),
    "regex_match_index": frozenset(("GLOBAL_MATCH_DATA_INDEX",)),
}


def name_token(kind, raw, mode, context):
    if kind not in CONTEXT_KINDS[context]: return False
    if context == "type_self": return raw == "self"
    if context == "module_segment": return bool(re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z][a-z0-9]*)*", raw))
    if context == "special_global": return raw == kind
    if context == "regex_match_index":
        if not re.fullmatch(r"\$(?:0|[1-9][0-9]*\??)", raw): return False
        digits = raw[1:].rstrip("?")
        return len(digits) < 10 or (len(digits) == 10 and digits <= "2147483647")
    if kind in NAME_OPERATORS: return raw == kind
    prefix = {"INSTANCE_VAR": "@", "CLASS_VAR": "@@"}.get(kind, "")
    if not raw.startswith(prefix): return False
    name = raw[len(prefix):]
    if kind == "IDENT" and name.endswith(("?", "!")):
        if mode == "Iyi" and name.endswith("!"): return False
        name = name[:-1]
    def start(char):
        return char == "_" or "a" <= char <= "z" or "A" <= char <= "Z" or ord(char) > 0x9f
    if not name or not start(name[0]) or any(not (start(c) or "0" <= c <= "9") for c in name[1:]):
        return False
    if kind == "IDENT" and (name[0].isupper() or name[0].istitle()): return False
    if kind == "CONST" and not (name[0].isupper() or name[0].istitle()): return False
    return not (kind == "IDENT" and raw == "_")


def source_name(value, depth):
    fields(value, "lexical_origin binding_origin context input_sha256 input_bytesize input_start input_end lexical_mode token_kind raw_text")
    lexical = value["lexical_origin"]
    anchor = origin(lexical, depth + 1)
    context = value["context"]
    if context not in NAME_CONTEXTS or not (anchor == ("Name", context) or (context in ("method_name", "local_reference") and anchor == ("Call", "method"))):
        raise ValueError("invalid source name role")
    binding = value["binding_origin"]
    if binding is not None:
        origin(binding, depth + 1)
        if (binding.get("kind") != "Synthetic" or binding.get("synthesis_kind") != "local_binding" or
                binding.get("structural_slot") != "assignment" or binding.get("parent_origin") != lexical or
                anchor != ("Call", "method")):
            raise ValueError("invalid source binding ancestry")
    guard(value["input_sha256"])
    for key in ("input_bytesize", "input_start", "input_end"): number(value[key])
    token_fields(value)
    text(value["raw_text"])
    if not name_token(value["token_kind"], value["raw_text"], value["lexical_mode"], context):
        raise ValueError("source token disagrees with name context")
    raw = value["raw_text"].encode("utf-8")
    start, end = value["input_start"], value["input_end"]
    if not 0 <= start < end <= value["input_bytesize"] or end - start != len(raw):
        raise ValueError("invalid source token span")
    if lexical["kind"] == "Written":
        if lexical["input_byte_offset"] != start: raise ValueError("source origin offset mismatch")
    elif lexical["kind"] == "Expanded":
        event = lexical["token_event"]
        if (event["input_start"] != start or event["input_end"] != end or
                lexical["expansion_guard"] != "sha256:" + value["input_sha256"] or
                event["token_text"] != value["raw_text"] or event["token_kind"] != value["token_kind"] or
                event["lexical_mode"] != value["lexical_mode"] or event["selection"] != "Whole"):
            raise ValueError("expanded source token mismatch")
    else:
        raise ValueError("invalid lexical name origin")
    return raw

INVALID_PARAMETER_NAMES = frozenset("begin nil true false yield with abstract def macro require case select if unless include extend class struct module enum while until return next break lib fun alias pointerof sizeof offsetof instance_sizeof typeof private protected asm out self in end alignof instance_alignof".split())


def derived_name(value, depth):
    if value.get("derivation_kind") == "BoundProjection":
        return bound_projection(value, depth)
    if value.get("derivation_kind") == "ModuleHeaderPath":
        fields(value, "kind derivation_kind module_header_origin source_segments package_name result_index")
        header = value["module_header_origin"]
        if (not isinstance(header, dict) or header.get("kind") not in ("Written", "Expanded") or
                origin(header, depth + 1) != ("ModuleHeader", "keyword")):
            raise ValueError("invalid module header origin")
        segments = value["source_segments"]
        if not isinstance(segments, list) or not segments: raise ValueError("missing module path segments")
        previous, common, names = -1, None, []
        for segment in segments:
            raw = source_name(segment, depth)
            if segment["context"] != "module_segment" or segment["binding_origin"] is not None or segment["input_start"] < previous:
                raise ValueError("invalid module segment")
            lexical = segment["lexical_origin"]
            identity = ((lexical["kind"], lexical["source_identity"]) if lexical["kind"] == "Written" else
                        (lexical["kind"], lexical["invocation_origin"], lexical["macro_definition_origin"], lexical["expansion_guard"]))
            identity = (segment["input_sha256"], segment["input_bytesize"], segment["lexical_mode"], identity)
            if common is not None and identity != common: raise ValueError("module segment input mismatch")
            common, previous = identity, segment["input_end"]
            names.append(raw.decode("utf-8"))
        package = value["package_name"]
        if package is not None:
            text(package)
            if names[0] != package: names.insert(0, package)
        number(value["result_index"])
        if value["result_index"] >= len(names): raise ValueError("invalid module segment index")
        selected = names[value["result_index"]]
        result, first, underscore = "", True, False
        for char in selected:
            if first: result += char.title()
            elif char == "_": underscore = True
            elif underscore:
                result += char.title()
                underscore = False
            else: result += char
            first = False
        if not name_token("CONST", result, "Iyi", "path_segment"): raise ValueError("invalid rendered module segment")
        return (("Name", "path_segment"), result.encode("utf-8"))
    if value.get("derivation_kind") == "ImplicitModuleSelf":
        fields(value, "kind derivation_kind module_header_origin")
        header = value["module_header_origin"]
        if (not isinstance(header, dict) or header.get("kind") not in ("Written", "Expanded") or
                origin(header, depth + 1) != ("ModuleHeader", "keyword")):
            raise ValueError("invalid implicit module self origin")
        return (("Name", "type_self"), b"self")
    if value.get("derivation_kind") == "TypeSugar":
        fields(value, "kind derivation_kind production witnesses result lowering_index")
        matrix = {
            "Pointer": (("*",), {("Pointer", 0)}),
            "DoublePointer": (("**",), {("Pointer", 0), ("Pointer", 1)}),
            "NilableType": (("?",), {("Nil", 0)}),
            "NilableExpression": (("?",), {("Union", 0), ("Nil", 0)}),
            "SelfNilableType": (("self?",), {("Nil", 0), ("Self", 0)}),
            "StaticArray": (("[", "]"), {("StaticArray", 0)}),
            "Tuple": (("{", "}"), {("Tuple", 0)}),
            "NamedTuple": (("{", "}"), {("NamedTuple", 0)}),
            "NilPredicate": (("nil?",), {("Nil", 0)}),
        }
        production = value["production"]
        if production not in matrix: raise ValueError("unknown type sugar")
        number(value["lowering_index"])
        spellings, results = matrix[production]
        if (value["result"], value["lowering_index"]) not in results: raise ValueError("invalid type sugar result")
        witnesses = value["witnesses"]
        if not isinstance(witnesses, list) or len(witnesses) != len(spellings): raise ValueError("invalid type sugar witnesses")
        previous, common = -1, None
        for witness, spelling in zip(witnesses, spellings):
            fields(witness, "lexical_origin input_sha256 input_bytesize input_start input_end lexical_mode token_kind raw_text")
            if origin(witness["lexical_origin"], depth + 1) != ("TypeSyntax", "token"): raise ValueError("invalid type syntax origin")
            guard(witness["input_sha256"])
            for key in ("input_bytesize", "input_start", "input_end"): number(witness[key])
            token_fields(witness); text(witness["raw_text"])
            expected_kind = "IDENT" if spelling in ("self?", "nil?") else spelling
            if (witness["token_kind"] != expected_kind or witness["raw_text"] != spelling or
                    witness["input_start"] < previous or witness["input_end"] > witness["input_bytesize"] or
                    witness["input_end"] - witness["input_start"] != len(spelling.encode("utf-8"))):
                raise ValueError("invalid type syntax token")
            lexical = witness["lexical_origin"]
            if lexical["kind"] == "Written":
                if lexical["input_byte_offset"] != witness["input_start"]: raise ValueError("type syntax offset mismatch")
            elif lexical["kind"] == "Expanded":
                event = lexical["token_event"]
                if (lexical["expansion_guard"] != "sha256:" + witness["input_sha256"] or event["selection"] != "Whole" or
                        event["input_start"] != witness["input_start"] or event["input_end"] != witness["input_end"] or
                        event["token_kind"] != witness["token_kind"] or event["token_text"] != spelling or
                        event["lexical_mode"] != witness["lexical_mode"]):
                    raise ValueError("expanded type syntax mismatch")
            else: raise ValueError("invalid type syntax source")
            source_identity = (lexical["kind"], lexical["source_identity"]) if lexical["kind"] == "Written" else (
                lexical["kind"], lexical["invocation_origin"], lexical["macro_definition_origin"], lexical["expansion_guard"])
            identity = (witness["input_sha256"], witness["input_bytesize"], witness["lexical_mode"], source_identity)
            if common is not None and common != identity: raise ValueError("type syntax input mismatch")
            common, previous = identity, witness["input_end"]
        return (("Name", "type_self" if value["result"] == "Self" else "path_segment"), b"self" if value["result"] == "Self" else value["result"].encode("utf-8"))
    if value.get("derivation_kind") == "RegexMatchIndex":
        fields(value, "kind derivation_kind source_token result")
        source = value["source_token"]
        raw = source_name(source, depth)
        if source["context"] != "regex_match_index" or origin(source["lexical_origin"], depth + 1) != ("Name", "regex_match_index"):
            raise ValueError("invalid regex derivation source")
        if value["result"] == "MatchData": return (("Name", "special_global"), b"$~")
        if value["result"] == "Lookup": return (("Call", "method"), b"[]?" if raw.endswith(b"?") else b"[]")
        raise ValueError("invalid regex derivation result")
    if value.get("derivation_kind") != "ParameterLowering": raise ValueError("unknown derived name operation")
    fields(value, "kind derivation_kind source_token definition_origin parameter_slot parameter_index result projection fresh_index")
    source = value["source_token"]
    raw = source_name(source, depth)
    if (source["context"] != "parameter" or
            origin(source["lexical_origin"], depth + 1) != ("Name", "parameter")):
        raise ValueError("invalid derived source role")
    prefix = {"INSTANCE_VAR": b"@", "CLASS_VAR": b"@@"}.get(source["token_kind"])
    if prefix is None or not raw.startswith(prefix): raise ValueError("invalid variable prefix")
    if origin(value["definition_origin"], depth + 1) != ("Def", "keyword"):
        raise ValueError("invalid derived definition owner")
    if value["parameter_slot"] not in ("positional", "double_splat", "block"):
        raise ValueError("invalid parameter slot")
    number(value["parameter_index"])
    if value["parameter_slot"] != "positional" and value["parameter_index"] != 0:
        raise ValueError("noncanonical parameter index")
    stem = raw[len(prefix):]
    invalid_stem = stem.decode("utf-8") in INVALID_PARAMETER_NAMES
    result, projection, fresh = value["result"], value["projection"], value["fresh_index"]
    if result == "Target" and projection == "Whole" and fresh is None:
        return (("Name", "instance_variable" if len(prefix) == 1 else "class_variable"), raw)
    if result == "DefaultExternal" and projection == "StripVariablePrefix" and fresh is None and invalid_stem:
        return (("Name", "named_entry"), stem)
    if result in ("Argument", "LocalValue"):
        role = "parameter" if result == "Argument" else "local_reference"
        if projection == "StripVariablePrefix" and fresh is None and not invalid_stem:
            return (("Name", role), stem)
        if projection == "FreshParameterName" and invalid_stem:
            number(fresh)
            return (("Name", role), ("__arg" + str(fresh)).encode("utf-8"))
    raise ValueError("invalid derived name operation")


def name_value(value, depth):
    if not isinstance(value, dict): raise ValueError("invalid name value")
    if value.get("kind") == "Observed":
        fields(value, "kind source_token")
        return source_name(value["source_token"], depth)
    if value.get("kind") == "Derived":
        fields(value, "kind origin")
        if not isinstance(value["origin"], dict) or value["origin"].get("kind") != "DerivedName":
            raise ValueError("invalid derived name value")
        return derived_name(value["origin"], depth + 1)[1]
    raise ValueError("unknown name value")


def bound_projection(value, depth):
    fields(value, "kind derivation_kind producer source_fragment_sha256 source_text source_names output_text lexical_mode result_start result_end token_kind context")
    source, output = value["source_text"], value["output_text"]
    if not isinstance(source, str) or not isinstance(output, str): raise ValueError("invalid projection text")
    if source: raise ValueError("bound projection requires authoritative source inventory")
    try: source_bytes, output_bytes = source.encode("utf-8"), output.encode("utf-8")
    except UnicodeError as exc: raise ValueError("invalid projection UTF-8") from exc
    guard(value["source_fragment_sha256"])
    if hashlib.sha256(source_bytes).hexdigest() != value["source_fragment_sha256"]: raise ValueError("projection source guard mismatch")
    names = value["source_names"]
    if not isinstance(names, list): raise ValueError("invalid projection names")
    cursor = 0
    for entry in names:
        fields(entry, "start_offset end_offset name")
        number(entry["start_offset"]); number(entry["end_offset"])
        start, end = entry["start_offset"], entry["end_offset"]
        if not cursor <= start < end <= len(source_bytes): raise ValueError("invalid projection source span")
        try: source_bytes[start:end].decode("utf-8")
        except UnicodeError as exc: raise ValueError("invalid projection source UTF-8 boundary") from exc
        if source_bytes[start:end] != name_value(entry["name"], depth): raise ValueError("projection source name differs")
        cursor = end
    producer = value["producer"]
    if not isinstance(producer, dict): raise ValueError("invalid projection producer")
    for field in producer.values():
        if isinstance(field, str):
            try: field.encode("utf-8")
            except UnicodeError as exc: raise ValueError("invalid producer UTF-8") from exc
    kind = producer.get("kind")
    permitted = ("path_segment", "named_entry", "type_self")
    if kind == "StripRoot":
        fields(producer, "kind root"); text(producer["root"])
        prefix = producer["root"] + "::"
        if not names or not source.startswith(prefix): raise ValueError("invalid root projection")
        actual, permitted = source[len(prefix):], ("path_segment",)
    elif kind == "ForeignType":
        fields(producer, "kind module_name source_name qualified_name")
        for key in ("module_name", "source_name", "qualified_name"): text(producer[key])
        old = producer["source_name"]
        if not names or not (source == old or source.startswith(old + "::")): raise ValueError("invalid foreign projection")
        actual, permitted = producer["qualified_name"] + source[len(old):], ("path_segment",)
    elif kind == "AliasType":
        fields(producer, "kind owner name resolved_type")
        for key in ("owner", "name", "resolved_type"): text(producer[key])
        if not names or source != producer["name"]: raise ValueError("invalid alias projection")
        actual = producer["resolved_type"]
    elif kind == "SelfReturn":
        fields(producer, "kind owner_type method_name receiver"); text(producer["owner_type"])
        if not names or source != producer["owner_type"] or producer["method_name"] != "new" or producer["receiver"] != "self":
            raise ValueError("invalid self return")
        actual, permitted = "self", ("type_self",)
    elif kind == "SemanticSignatureType":
        fields(producer, "kind definition_origin field parameter_index semantic_type"); text(producer["semantic_type"])
        if source or names or origin(producer["definition_origin"], depth + 1) != ("Def", "keyword"):
            raise ValueError("invalid signature producer")
        if producer["field"] == "return_type":
            if producer["parameter_index"] is not None: raise ValueError("invalid return index")
        elif producer["field"] == "parameter_restriction":
            number(producer["parameter_index"])
        else: raise ValueError("unknown signature field")
        actual = producer["semantic_type"]
    elif kind == "UninitializedClassVar":
        fields(producer, "kind declaration_origin owner_type variable_name semantic_type")
        text(producer["owner_type"]); text(producer["semantic_type"]); text(producer["variable_name"])
        if (source or names or origin(producer["declaration_origin"], depth + 1) != ("Name", "class_variable") or
                not name_token("CLASS_VAR", producer["variable_name"], value["lexical_mode"], "class_variable")):
            raise ValueError("invalid uninitialized class variable")
        actual = "uninitialized " + producer["semantic_type"]
    elif kind == "ConstantAccessor":
        fields(producer, "kind definition_origin prefix constant_name part")
        if not isinstance(producer["prefix"], str): raise ValueError("invalid accessor prefix")
        text(producer["constant_name"])
        definition = producer["definition_origin"]
        if (source or names or origin(definition, depth + 1) != ("Def", "keyword") or
                definition.get("kind") != "Synthetic" or definition.get("synthesis_kind") != "constant_accessor" or
                definition.get("structural_slot") != "getter"):
            raise ValueError("invalid accessor producer")
        if producer["part"] == "Name":
            actual, permitted = (producer["prefix"] + producer["constant_name"]).lower(), ("definition_name",)
        elif producer["part"] == "Receiver": actual, permitted = "self", ("local_reference",)
        else: raise ValueError("invalid accessor part")
    elif kind == "ResolvedRestriction":
        fields(producer, "kind owner_type written_type resolved_type root add_global")
        for key in ("owner_type", "written_type", "resolved_type"): text(producer[key])
        if not isinstance(producer["root"], str) or type(producer["add_global"]) is not bool or not names or source != producer["written_type"]:
            raise ValueError("invalid resolved restriction")
        resolved = producer["resolved_type"]
        if producer["add_global"] and (resolved.startswith("::") or not resolved.partition("::")[0] or resolved.partition("::")[0] == producer["root"]):
            raise ValueError("invalid global restriction")
        actual = ("::" if producer["add_global"] else "") + resolved
    else: raise ValueError("unknown bound producer")
    if output != actual or value["context"] not in permitted: raise ValueError("invalid bound projection result")
    if value["lexical_mode"] not in ("Crystal", "Iyi"): raise ValueError("invalid projection lexical mode")
    number(value["result_start"]); number(value["result_end"])
    start, end = value["result_start"], value["result_end"]
    if not 0 <= start < end <= len(output_bytes) or (kind == "UninitializedClassVar" and start < len(b"uninitialized ")):
        raise ValueError("invalid projection result span")
    try:
        before, selected, after = output_bytes[:start].decode("utf-8"), output_bytes[start:end].decode("utf-8"), output_bytes[end:].decode("utf-8")
    except UnicodeError as exc: raise ValueError("invalid projection UTF-8 boundary") from exc
    if not name_token(value["token_kind"], selected, value["lexical_mode"], value["context"]):
        raise ValueError("invalid projection result token")
    quote, comment, escaped = None, False, False
    for index, char in enumerate(before):
        if comment:
            if char == "\n": comment = False
        elif quote is not None:
            if escaped: escaped = False
            elif char == "\\": escaped = True
            elif char == quote: quote = None
        elif char == "#": comment = True
        elif char in "\"'`": quote = char
        elif char == "%" and index + 1 < len(before) and (before[index + 1].isalpha() or before[index + 1] in "([{<|"):
            raise ValueError("ambiguous preceding percent literal")
    if quote is not None or comment: raise ValueError("projection lies inside a literal or comment")
    def ident_char(c): return c == "_" or c.isascii() and c.isalnum() or ord(c) > 0x9f
    if before and (ident_char(before[-1]) or before[-1] in "@$"): raise ValueError("projection starts inside token")
    if after and (ident_char(after[0]) or (value["token_kind"] == "IDENT" and
            (after[0] == "?" or (after[0] == "!" and value["lexical_mode"] == "Crystal")) and not after.startswith(("?=", "!=")))):
        raise ValueError("projection ends inside token")
    following = re.sub(r"\A(?:\s+|#[^\n]*(?:\n|\Z))*", "", after)
    named_entry = following.startswith(":") and not following.startswith("::")
    if (value["context"] == "named_entry") != named_entry:
        raise ValueError("invalid projected type position")
    return (("Name", value["context"]), selected.encode("utf-8"))


RAW_PRODUCERS = frozenset("MacroTemplate MacroId MacroVar MacroVerbatim YieldWrapper SemanticPrinter".split())
HEAD_ROLES = {"NamedArrayHead": ("Literal", "array"), "NamedHashHead": ("Literal", "hash"),
              "ConstantAssignHead": ("Assign", "constant"), "ConstantTypeHead": ("Assign", "constant"),
              "MultiAssignHead": ("Literal", "multiassign")}
WITNESS_FORMS = {"NamedArrayHead": (("Open", "{"),), "NamedHashHead": (("Open", "{"),),
                 "ConstantAssignHead": (("Equals", "="),),
                 "ConstantTypeHead": (("Colon", ":"), ("Equals", "="))}
SCOPE_KEYS = ("invocation_origin", "macro_definition_origin", "expansion_guard")


def raw_event(event, expected, mode, depth):
    fields(event, "input_start input_end token_kind token_text lexical_mode selection byte_parts")
    token_fields(event)
    for key in ("input_start", "input_end"): number(event[key])
    if (event["lexical_mode"] != mode or event["selection"] != "Whole" or
            event["token_kind"] != expected or event["token_text"] != expected or event["input_end"] - event["input_start"] != len(expected.encode())):
        raise ValueError("invalid raw syntax witness")
    parts = event["byte_parts"]
    if not isinstance(parts, list) or not parts: raise ValueError("missing raw witness parts")
    cursor = event["input_start"]
    for part in parts:
        fields(part, "kind start_offset end_offset emitter_origin producer")
        for key in ("start_offset", "end_offset"): number(part[key])
        if (part["kind"] != "Generated" or part["producer"] not in RAW_PRODUCERS or
                part["start_offset"] != cursor or not cursor < part["end_offset"] <= event["input_end"]):
            raise ValueError("invalid raw syntax producer")
        if part["emitter_origin"] is not None and origin(part["emitter_origin"], depth + 1) not in (("MacroDirective", "expression"), ("MacroDirective", "control")):
            raise ValueError("invalid raw witness emitter")
        cursor = part["end_offset"]
    if cursor != event["input_end"]: raise ValueError("incomplete raw witness")


def shared_scope(left, right):
    return all(left[k] == right[k] for k in SCOPE_KEYS)


def anchor_use(value, depth):
    use, event = value["anchor_use"], value["token_event"]
    tag = use["kind"]
    if tag == "Direct": return
    if tag == "HeadOf":
        fields(use, "kind rule evidence head emitter_origin")
        rule = use["rule"]
        if rule not in HEAD_ROLES or (value["anchor_kind"], value["role"]) != HEAD_ROLES[rule]:
            raise ValueError("invalid head rule")
        head = use["head"]
        if not isinstance(head, dict): raise ValueError("invalid head")
        if head.get("kind") == "Anchor":
            fields(head, "kind origin")
            child = head["origin"]
            child_role = origin(child, depth + 1)
            allowed = {("Name", "path_segment")}
            if rule == "MultiAssignHead":
                allowed |= {("Call", "method"), ("Name", "local_reference"), ("Name", "instance_variable"),
                            ("Name", "class_variable"), ("Name", "special_global"), ("ProcLiteral", "arrow"),
                            ("ProcPointer", "arrow"), ("Cast", "keyword")}
                allowed |= {("Literal", role) for role in ("array", "hash", "regex", "interpolation", "range", "case", "select")}
            if (child_role not in allowed or child.get("kind") != "Expanded" or child["anchor_use"] != {"kind": "Direct"} or
                    not shared_scope(value, child) or child["token_event"] != event):
                raise ValueError("invalid head child")
        elif head.get("kind") == "Syntax":
            fields(head, "kind form adjacent_name_origin")
            form = head["form"]
            allowed = {"GlobalPathPrefix": "::", "FirstSplat": "*", "FirstUnderscore": "_", "ParenthesizedFirstTarget": "("}
            if form not in allowed or event["token_kind"] != allowed[form] or event["token_text"] != allowed[form] or event["selection"] != "Whole":
                raise ValueError("invalid syntax head")
            adjacent = head["adjacent_name_origin"]
            if form == "GlobalPathPrefix":
                if (origin(adjacent, depth + 1) != ("Name", "path_segment") or adjacent.get("kind") != "Expanded" or
                        not shared_scope(value, adjacent) or adjacent["anchor_use"] != {"kind": "Direct"} or
                        adjacent["token_event"]["input_start"] != event["input_end"] or
                        adjacent["token_event"]["selection"] != "Whole" or adjacent["token_event"]["token_kind"] != "CONST" or
                        adjacent["token_event"]["lexical_mode"] != event["lexical_mode"]):
                    raise ValueError("invalid global path head")
            elif rule != "MultiAssignHead" or adjacent is not None:
                raise ValueError("invalid first target syntax")
        else: raise ValueError("unknown head")
    elif tag == "PayloadOf":
        fields(use, "kind rule evidence owner_origin emitter_origin")
        owner = use["owner_origin"]
        owner_role = origin(owner, depth + 1)
        rule = use["rule"]
        if ((value["anchor_kind"], value["role"]) != ("Literal", "interpolation") or value["name_context"] is not None or
                owner.get("kind") != "Expanded" or owner["anchor_use"] != {"kind": "Direct"} or
                not shared_scope(value, owner) or owner["token_event"] != event):
            raise ValueError("invalid payload owner")
        opener = event["token_text"]
        if event["token_kind"] != "DELIMITER_START" or event["selection"] != "Whole": raise ValueError("invalid payload delimiter")
        if rule == "RegexInterpolationPayload":
            if owner_role != ("Literal", "regex") or not (opener == "/" or (len(opener) == 3 and opener[:2] == "%r" and opener[2] in "(<[{|")): raise ValueError("invalid regex owner")
        elif rule == "CommandInterpolationPayload":
            if owner_role != ("Call", "method") or not (opener == "`" or (len(opener) == 3 and opener[:2] == "%x" and opener[2] in "(<[{|")): raise ValueError("invalid command owner")
        else: raise ValueError("unknown payload rule")
    else: raise ValueError("unknown anchor use")
    evidence = use["evidence"]
    if not isinstance(evidence, dict): raise ValueError("invalid use evidence")
    emitter = use["emitter_origin"]
    if emitter is not None and origin(emitter, depth + 1) not in (("MacroDirective", "expression"), ("MacroDirective", "control")):
        raise ValueError("invalid anchor use emitter")
    if evidence.get("kind") in ("RawSyntax", "DerivedFromOwner") and emitter is not None:
        raise ValueError("invalid inferred emitter")
    if evidence.get("kind") == "Spliced":
        fields(evidence, "kind source_origin")
        if origin(evidence["source_origin"], depth + 1) != (value["anchor_kind"], value["role"]):
            raise ValueError("invalid preserved parent")
    elif evidence.get("kind") == "Constructed":
        fields(evidence, "kind producer")
        if evidence["producer"] != "ConstructedAst": raise ValueError("invalid constructed parent")
    elif evidence.get("kind") == "DerivedFromOwner":
        fields(evidence, "kind")
        if tag != "PayloadOf" or any(part.get("kind") != "Generated" or part.get("producer") not in RAW_PRODUCERS for part in event["byte_parts"]):
            raise ValueError("invalid derived payload")
    elif evidence.get("kind") == "RawSyntax":
        fields(evidence, "kind witnesses")
        if tag != "HeadOf": raise ValueError("invalid raw syntax use")
        witnesses = evidence["witnesses"]
        if not isinstance(witnesses, list): raise ValueError("invalid witnesses")
        forms = WITNESS_FORMS.get(rule)
        if rule == "MultiAssignHead":
            forms = (("Splat", "*"), ("Equals", "=")) if use["head"].get("form") == "FirstSplat" else (("Comma", ","), ("Equals", "="))
        if forms is None or len(witnesses) != len(forms): raise ValueError("missing raw syntax witnesses")
        last = event["input_end"]
        for index, (witness, (role, spelling)) in enumerate(zip(witnesses, forms)):
            fields(witness, "role event")
            same_splat = rule == "MultiAssignHead" and role == "Splat" and index == 0
            if (witness["role"] != role or
                    (witness["event"] != event if same_splat else witness["event"]["input_start"] < last)):
                raise ValueError("invalid witness order")
            raw_event(witness["event"], spelling, event["lexical_mode"], depth)
            last = witness["event"]["input_end"]
    else: raise ValueError("unknown use evidence")


def origin(value, depth=0):
    if depth > 128 or not isinstance(value, dict):
        raise ValueError("invalid origin depth")
    kind = value.get("kind")
    if kind == "Written":
        fields(value, "kind source_identity input_byte_offset anchor_kind role")
        source = fields(value["source_identity"], "module file")
        text(source["module"]); text(source["file"]); number(value["input_byte_offset"])
    elif kind == "Synthetic":
        fields(value, "kind parent_origin synthesis_kind structural_slot")
        parent = origin(value["parent_origin"], depth + 1)
        text(value["synthesis_kind"]); text(value["structural_slot"])
        key = (value["synthesis_kind"], value["structural_slot"])
        if ((key == ("block_to_proc", "proc") and parent in (("Block", "opener"), ("Block", "ampersand"))) or
            (key == ("proc_pointer", "proc") and parent == ("ProcPointer", "arrow")) or
            (key == ("defer", "cleanup") and parent == ("Defer", "keyword"))):
            return ("ProcLiteral", "arrow")
        if key == ("inline_macro_definition", "macro") and parent in (("MacroDirective", "expression"), ("MacroDirective", "control")):
            return ("Macro", "keyword")
        if key == ("implicit_module_self", "extend") and parent == ("ModuleHeader", "keyword") and value["parent_origin"].get("kind") in ("Written", "Expanded"):
            return ("Extend", "keyword")
        if ((key == ("literal_expansion_node", "regex:interpolation") and parent == ("Literal", "regex")) or
                (key == ("literal_expansion_node", "command:interpolation") and parent == ("Call", "method"))):
            return ("Literal", "interpolation")
        synth, slot = key
        index = lambda value: bool(re.fullmatch(r"0|[1-9][0-9]*", value)) and (len(value) < 10 or (len(value) == 10 and value <= "2147483647"))
        if synth == "select_cast" and parent == ("Literal", "select") and slot.startswith("arm:") and index(slot[4:]):
            return ("Cast", "keyword")
        if key == ("cast_error_interpolation", "message") and parent == ("Cast", "keyword"):
            return ("Literal", "interpolation")
        if synth == "literal_expansion_node":
            fixed = {("derive:fields", ("Call", "method")): ("Literal", "array"),
                     ("select:multiassign", ("Literal", "select")): ("Literal", "multiassign"),
                     ("select:case", ("Literal", "select")): ("Literal", "case")}
            if (slot, parent) in fixed: return fixed[(slot, parent)]
            pieces = slot.split(":")
            if len(pieces) == 3 and pieces[:2] == ["array", "interpolation"] and index(pieces[2]) and parent == ("Literal", "array"):
                return ("Literal", "interpolation")
            if len(pieces) >= 2 and pieces[0] == "block_unpack" and all(index(part) for part in pieces[1:]) and parent in (("Block", "opener"), ("Block", "ampersand")):
                return ("Literal", "multiassign")
            if len(pieces) == 3 and pieces[:2] == ["multiassign", "range"] and index(pieces[2]) and parent == ("Literal", "multiassign"):
                return ("Literal", "range")
        if synth == "literal_expansion":
            pieces = slot.split(":")
            if len(pieces) == 3 and pieces[:2] == ["array", "block"] and index(pieces[2]) and parent == ("Literal", "array"):
                return ("Block", "opener")
            if len(pieces) >= 2 and parent == ("Literal", pieces[0]):
                fixed = {"array": {"constructor", "buffer"}, "hash": {"constructor"}, "range": {"constructor"},
                         "regex": {"constructor", "options", "compile"}, "interpolation": {"call"},
                         "select": {"select", "invalid"}, "multiassign": {"size", "compare", "error", "raise"}}
                indexed = {"array": {"concat", "append", "store", "element_type", "each", "each_body"},
                           "hash": {"store"}, "multiassign": {"index"}}
                if len(pieces) == 2 and pieces[1] in fixed.get(pieces[0], set()): return ("Call", "method")
                if len(pieces) == 3 and pieces[1] in indexed.get(pieces[0], set()) and index(pieces[2]): return ("Call", "method")
                if len(pieces) == 5 and pieces[:2] == ["case", "compare"] and all(index(part) for part in pieces[2:]): return ("Call", "method")
        if ((key == ("proc_pointer_invoke", "call") and parent == ("ProcPointer", "arrow")) or
                (synth == "recover_panic" and slot in ("message", "raise") and parent == ("Call", "method")) or
                (synth == "defer_runtime" and slot in ("push", "pop") and parent == ("Defer", "keyword")) or
                (synth == "compound_assignment" and slot in ("getter", "setter") and parent == ("Call", "method"))):
            return ("Call", "method")
        if synth == "group_lowering" and parent == ("Call", "method"):
            if slot in ("join", "first_failure"): return ("Call", "method")
            pieces = slot.split(":")
            if len(pieces) == 2 and pieces[0] in ("value", "fiber", "object_id", "compare") and index(pieces[1]):
                return ("Call", "method")
        if key == ("constant_accessor", "getter") and parent == ("Assign", "constant"):
            return ("Def", "keyword")
        return ("Synthetic", value["synthesis_kind"])
    elif kind == "DerivedName":
        return derived_name(value, depth)[0]
    elif kind == "Expanded":
        fields(value, "kind invocation_origin macro_definition_origin expansion_guard anchor_kind role name_context token_event anchor_use")
        invocation = origin(value["invocation_origin"], depth + 1)
        definition = origin(value["macro_definition_origin"], depth + 1)
        if invocation not in (("Call", "method"), ("MacroDirective", "expression"), ("MacroDirective", "control"),
                              ("Include", "keyword"), ("Extend", "keyword"), ("ClassDef", "keyword"),
                              ("Def", "keyword"), ("Macro", "keyword")) or definition != ("Macro", "keyword"):
            raise ValueError("invalid macro ancestry")
        guard(value["expansion_guard"], "sha256:")
        event = fields(value["token_event"], "input_start input_end token_kind token_text lexical_mode selection byte_parts")
        number(event["input_start"]); number(event["input_end"])
        token_fields(event)
        text(value["anchor_kind"]); text(value["role"]); text(event["token_text"])
        output = event["token_text"].encode("utf-8")
        start, measured_end = event["input_start"], event["input_end"]
        if measured_end <= start or measured_end - start != len(output): raise ValueError("invalid generated token span")
        use = value["anchor_use"]
        if not isinstance(use, dict) or use.get("kind") not in ("Direct", "HeadOf", "PayloadOf"):
            raise ValueError("invalid anchor use")
        direct = use["kind"] == "Direct"
        if direct: fields(use, "kind")
        if event["selection"] == "Whole": finish = measured_end
        elif event["selection"] == "SignedNumberSign":
            if (not direct or (value["anchor_kind"], value["role"]) != ("Call", "method") or
                    event["token_kind"] != "NUMBER" or len(output) < 2 or
                    output[:1] not in (b"+", b"-") or output[1:2] not in tuple(bytes([i]) for i in range(48, 58))):
                raise ValueError("invalid signed number selection")
            finish = start + 1
            output = output[:1]
        else: raise ValueError("unknown token selection")
        context = value["name_context"]
        if value["anchor_kind"] == "Name" and context is None: raise ValueError("missing name context")
        if context is not None and context not in NAME_CONTEXTS: raise ValueError("unknown name context")
        if context is not None and not ((value["anchor_kind"], value["role"]) == ("Name", context) or
                                        (value["anchor_kind"], value["role"], context) == ("Call", "method", "method_name")):
            raise ValueError("name context on structural anchor")
        if context is not None and not name_token(event["token_kind"], event["token_text"], event["lexical_mode"], context):
            raise ValueError("receiving token disagrees with name context")
        parts = event["byte_parts"]
        if not isinstance(parts, list) or not parts: raise ValueError("missing emission parts")
        end = start
        for part in parts:
            if not isinstance(part, dict): raise ValueError("invalid emission part")
            tag = part.get("kind")
            if tag == "Generated":
                fields(part, "kind start_offset end_offset emitter_origin producer")
                if part["producer"] not in PRODUCERS: raise ValueError("unknown producer")
            elif tag == "AstAnchor":
                fields(part, "kind start_offset end_offset emitter_origin source_origin")
                source_role = origin(part["source_origin"], depth + 1)
                if len(parts) != 1 or (direct and source_role != (value["anchor_kind"], value["role"])):
                    raise ValueError("invalid structural source")
            elif tag == "NameSplice":
                fields(part, "kind start_offset end_offset emitter_origin source_name")
                if direct and context is None: raise ValueError("name contribution without receiving context")
                raw = name_value(part["source_name"], depth)
            else:
                raise ValueError("unknown emission part")
            number(part["start_offset"]); number(part["end_offset"])
            emitter = part["emitter_origin"]
            if part["start_offset"] != end or not end < part["end_offset"] <= finish:
                raise ValueError("invalid emission part extent")
            try: output[part["start_offset"]-start:part["end_offset"]-start].decode("utf-8")
            except UnicodeDecodeError as exc: raise ValueError("emission splits UTF-8") from exc
            if emitter is not None and origin(emitter, depth + 1) not in (("MacroDirective", "expression"), ("MacroDirective", "control")):
                raise ValueError("invalid emitter")
            if tag == "NameSplice" and output[end-start:part["end_offset"]-start] != raw:
                raise ValueError("name contribution bytes differ")
            end = part["end_offset"]
        if end != finish: raise ValueError("incomplete token coverage")
        anchor_use(value, depth)
    else:
        raise ValueError("unknown origin")
    text(value["anchor_kind"]); text(value["role"])
    return value["anchor_kind"], value["role"]


def checked_origin(value):
    # Bound the unfolded structure before recursive validation or equality.
    stack, size = [(value, 0)], 0
    while stack:
        node, depth = stack.pop()
        # Tagged names add wrapper levels beyond an origin edge.
        if depth > 8 * 128 + 8: raise ValueError("origin nesting too deep")
        if isinstance(node, dict):
            size += 2 + max(0, len(node) - 1)
            for key, child in node.items():
                size += len(json.dumps(key, ensure_ascii=False).encode("utf-8")) + 1
                stack.append((child, depth + 1))
        elif isinstance(node, list):
            size += 2 + max(0, len(node) - 1)
            stack.extend((child, depth + 1) for child in node)
        else:
            size += len(json.dumps(node, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        if size > 8 * 1024 * 1024: raise ValueError("origin size limit exceeded")
    result = origin(value)
    events, stack = {}, [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("kind") == "Expanded":
                scope = json.dumps([node[k] for k in SCOPE_KEYS], sort_keys=True, separators=(",", ":"))
                associated = [node["token_event"]]
                use = node["anchor_use"]
                if use["kind"] == "HeadOf" and use["evidence"]["kind"] == "RawSyntax":
                    associated.extend(witness["event"] for witness in use["evidence"]["witnesses"])
                for event in associated:
                    key = (scope, event["input_start"])
                    if key in events and events[key] != event:
                        raise ValueError("conflicting token event identity")
                    events[key] = event
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return result


NOMINAL_TYPES = frozenset("NilType VoidType BoolType CharType IntegerType FloatType SymbolType NoReturnType PrimitiveType AliasType ClassType ModuleType EnumType NonGenericClassType NonGenericModuleType TraitType FileModule GenericClassType GenericModuleType GenericTraitType LibType".split())
UNION_TYPES = frozenset("UnionType NilableType NilableReferenceUnionType ReferenceUnionType NilableProcType MixedUnionType".split())


def type_identity(value, depth=0):
    if depth > 128 or not isinstance(value, dict): raise ValueError("invalid type")
    kind = value.get("kind")
    if not isinstance(kind, str) or not kind.startswith("Iyi::"): raise ValueError("unknown type")
    kind = kind[5:]
    if kind == "Program": fields(value, "kind")
    elif kind in NOMINAL_TYPES: text(fields(value, "kind name")["name"])
    elif kind in UNION_TYPES or kind == "TupleInstanceType":
        name = "members" if kind in UNION_TYPES else "elements"
        items = fields(value, "kind " + name)[name]
        if not isinstance(items, list): raise ValueError("invalid type list")
        for item in items: type_identity(item, depth + 1)
    elif kind in ("VirtualType", "MetaclassType", "VirtualMetaclassType", "GenericClassInstanceMetaclassType", "GenericModuleInstanceMetaclassType", "PointerInstanceType"):
        name = "base" if kind == "VirtualType" else "element" if kind == "PointerInstanceType" else "instance"
        type_identity(fields(value, "kind " + name)[name], depth + 1)
    elif kind == "ProcInstanceType":
        fields(value, "kind arguments return")
        if not isinstance(value["arguments"], list): raise ValueError("invalid proc arguments")
        for item in value["arguments"]: type_identity(item, depth + 1)
        type_identity(value["return"], depth + 1)
    elif kind in ("NamedTupleInstanceType", "GenericClassInstanceType", "GenericModuleInstanceType"):
        name = "entries" if kind == "NamedTupleInstanceType" else "parameters"
        fields(value, "kind " + name + ("" if name == "entries" else " owner"))
        if name == "parameters": text(value["owner"])
        if not isinstance(value[name], list): raise ValueError("invalid type entries")
        for item in value[name]:
            fields(item, "name type"); text(item["name"]); type_identity(item["type"], depth + 1)
    elif kind == "StaticArrayInstanceType":
        fields(value, "kind element size_kind size_value")
        type_identity(value["element"], depth + 1); text(value["size_kind"]); text(value["size_value"])
    elif kind == "TypeDefType":
        fields(value, "kind name target"); text(value["name"]); type_identity(value["target"], depth + 1)
    else: raise ValueError("unknown type")


def scope_identity(value, depth, current=False):
    if depth > 128 or not isinstance(value, dict): raise ValueError("invalid scope")
    kind = value.get("kind")
    if kind == "program" or (kind == "current_scope" and current): fields(value, "kind")
    elif kind in ("def", "block"):
        fields(value, "kind origin specialization"); checked_origin(value["origin"])
        (specialization_identity if kind == "def" else block_identity)(value["specialization"], depth + 1)
    else: raise ValueError("unknown scope")


def binding_identities(values, depth, semantic):
    if not isinstance(values, list): raise ValueError("invalid bindings")
    for value in values:
        fields(value, "name binding_origin scope type mutable" + (" closured assigned" if semantic else ""))
        text(value["name"]); checked_origin(value["binding_origin"]); scope_identity(value["scope"], depth + 1, semantic)
        binding = value["binding_origin"]
        if binding.get("kind") != "Synthetic": raise ValueError("invalid binding origin")
        parent = origin(binding["parent_origin"])
        role, slot = binding["synthesis_kind"], binding["structural_slot"]
        if role == "local_binding":
            valid = slot == "assignment" and parent == ("Call", "method")
        else:
            valid_slot = re.fullmatch(r"index:(0|[1-9][0-9]*)", slot) is not None
            allowed = {"parameter_binding": (("Def", "keyword"),),
                       "block_parameter": (("Block", "opener"), ("Block", "ampersand")),
                       "proc_parameter": (("ProcLiteral", "arrow"),)}
            valid = valid_slot and parent in allowed.get(role, ())
        if not valid: raise ValueError("invalid binding origin")
        type_identity(value["type"], depth + 1)
        for name in (("mutable", "closured", "assigned") if semantic else ("mutable",)):
            if type(value[name]) is not bool: raise ValueError("invalid binding flag")


def semantic_environment(value, depth):
    fields(value, "self_type lexical_scope_type bindings")
    for name in ("self_type", "lexical_scope_type"):
        if value[name] is not None: type_identity(value[name], depth + 1)
    binding_identities(value["bindings"], depth + 1, True)


def block_identity(value, depth):
    if depth > 128: raise ValueError("block nesting too deep")
    fields(value, "origin parameter_types return_type enclosing_specialization environment")
    checked_origin(value["origin"])
    if not isinstance(value["parameter_types"], list): raise ValueError("invalid block parameters")
    for item in value["parameter_types"]: type_identity(item, depth + 1)
    type_identity(value["return_type"], depth + 1)
    if value["enclosing_specialization"] is not None: specialization_identity(value["enclosing_specialization"], depth + 1)
    semantic_environment(value["environment"], depth + 1)


def specialization_identity(value, depth=0):
    if depth > 128 or not isinstance(value, dict): raise ValueError("invalid specialization")
    if value.get("kind") == "program_scope":
        source = fields(fields(value, "kind source_identity")["source_identity"], "module file")
        text(source["module"]); text(source["file"])
    elif value.get("kind") == "proc_scope":
        fields(value, "kind origin proc_type enclosing_specialization environment")
        checked_origin(value["origin"]); type_identity(value["proc_type"], depth + 1)
        if value["proc_type"]["kind"] != "Iyi::ProcInstanceType": raise ValueError("invalid proc scope")
        specialization_identity(value["enclosing_specialization"], depth + 1); semantic_environment(value["environment"], depth + 1)
    else:
        fields(value, "definition_origin dispatch_type defining_owner ordered_argument_types block_parameter_type named_argument_types free_variable_bindings expansion_shape lexical_block_specialization")
        checked_origin(value["definition_origin"]); type_identity(value["dispatch_type"], depth + 1); type_identity(value["defining_owner"], depth + 1)
        if not isinstance(value["ordered_argument_types"], list): raise ValueError("invalid arguments")
        for item in value["ordered_argument_types"]: type_identity(item, depth + 1)
        if value["block_parameter_type"] is not None: type_identity(value["block_parameter_type"], depth + 1)
        for name in ("named_argument_types", "free_variable_bindings"):
            if not isinstance(value[name], list): raise ValueError("invalid named types")
            for item in value[name]:
                fields(item, "name type"); text(item["name"]); type_identity(item["type"], depth + 1)
        shape = fields(value["expansion_shape"], "positional_count splat_index double_splat_name formal_parameters")
        number(shape["positional_count"])
        if shape["splat_index"] is not None: number(shape["splat_index"])
        if shape["double_splat_name"] is not None: text(shape["double_splat_name"])
        if not isinstance(shape["formal_parameters"], list): raise ValueError("invalid formals")
        for item in shape["formal_parameters"]:
            fields(item, "name external_name has_default"); text(item["name"]); text(item["external_name"])
            if type(item["has_default"]) is not bool: raise ValueError("invalid default")
        if value["lexical_block_specialization"] is not None: block_identity(value["lexical_block_specialization"], depth + 1)


def capture_environment(value, depth=0):
    if depth > 128: raise ValueError("environment too deep")
    fields(value, "captured_self_type bindings parent")
    if value["captured_self_type"] is not None: type_identity(value["captured_self_type"], depth + 1)
    binding_identities(value["bindings"], depth + 1, False)
    if value["parent"] is not None: capture_environment(value["parent"], depth + 1)


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate JSON key")
        result[key] = value
    return result

NATIVE_EVIDENCE_BUDGET = 64 * 1024 * 1024
CAPTURE_AUTHORITY_BUDGET = 64 * 1024 * 1024


def read_capture_authority(path, pinned_sha256):
    """Read an independently pinned index, without trusting artifact metadata."""
    guard(pinned_sha256)
    with open(path, "rb") as stream:
        data = stream.read(CAPTURE_AUTHORITY_BUDGET + 1)
    if len(data) > CAPTURE_AUTHORITY_BUDGET:
        raise ValueError("capture authority size limit exceeded")
    if hashlib.sha256(data).hexdigest() != pinned_sha256:
        raise ValueError("capture authority digest mismatch")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid capture authority JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("invalid capture authority index")
    return value


def macho_summary(data, expected_type):
    """Read a bounded, thin little-endian 64-bit Mach-O snapshot."""
    if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
        raise ValueError("unsupported or truncated Mach-O")
    _, cpu, subtype, file_type, ncmds, sizeofcmds, _, _ = struct.unpack_from("<8I", data)
    if cpu not in (0x01000007, 0x0100000c) or file_type != expected_type:
        raise ValueError("unsupported Mach-O CPU or file type")
    end = 32 + sizeofcmds
    if end > len(data) or ncmds > sizeofcmds // 8:
        raise ValueError("invalid Mach-O command area")
    sections, symtab, pos = [], None, 32
    budget = NATIVE_EVIDENCE_BUDGET
    for _ in range(ncmds):
        if pos + 8 > end: raise ValueError("truncated load command")
        cmd, size = struct.unpack_from("<II", data, pos)
        if size < 8 or size % 8 or pos + size > end:
            raise ValueError("invalid load command size")
        if cmd == 2:
            if size != 24 or symtab is not None: raise ValueError("invalid LC_SYMTAB")
            symtab = struct.unpack_from("<4I", data, pos + 8)
        elif cmd == 0x19:
            if size < 72: raise ValueError("truncated segment")
            nsects = struct.unpack_from("<I", data, pos + 64)[0]
            if nsects > (size - 72) // 80: raise ValueError("truncated sections")
            budget -= 256 * nsects
            if budget < 0: raise ValueError("native evidence size limit")
            for i in range(nsects):
                p = pos + 72 + 80 * i
                sect, seg = struct.unpack_from("<16s16s", data, p)
                address, length, offset = struct.unpack_from("<QQI", data, p + 32)
                flags = struct.unpack_from("<I", data, p + 64)[0]
                if address + length > 0xffffffffffffffff:
                    raise ValueError("section address overflow")
                kind = flags & 0xff
                if kind not in (1, 0xc, 0x12) and (offset > len(data) or length > len(data) - offset):
                    raise ValueError("section data outside file")
                sections.append({"index": len(sections) + 1,
                                 "segment_name_base64": base64.b64encode(seg).decode(),
                                 "section_name_base64": base64.b64encode(sect).decode(),
                                 "address": f"{address:016x}", "size": f"{length:016x}",
                                 "file_offset": offset, "flags": flags})
        pos += size
    if pos != end or symtab is None: raise ValueError("invalid Mach-O command count")
    symoff, nsyms, stroff, strsize = symtab
    if symoff > len(data) or nsyms > (len(data) - symoff) // 16 or stroff > len(data) or strsize > len(data) - stroff:
        raise ValueError("symbol table outside file")
    symend, strend = symoff + nsyms * 16, stroff + strsize
    def overlap(a, b, c, d):
        return a < b and c < d and a < d and c < b
    if overlap(symoff, symend, 0, end) or overlap(stroff, strend, 0, end) or overlap(symoff, symend, stroff, strend):
        raise ValueError("overlapping Mach-O tables")
    budget -= 256 * nsyms
    if budget < 0: raise ValueError("native evidence size limit")
    symbols = []
    for i in range(nsyms):
        strx, typ, sect, desc, value = struct.unpack_from("<IBBHQ", data, symoff + 16 * i)
        if strx:
            if strx >= strsize: raise ValueError("invalid symbol string index")
            start = stroff + strx
            scan_end = min(strend, start + budget + 1)
            stop = data.find(b"\0", start, scan_end)
            if stop < 0:
                if scan_end < strend: raise ValueError("native evidence size limit")
                raise ValueError("unterminated symbol name")
            length = stop - start
            budget -= length + 4 * ((length + 2) // 3)
            if budget < 0: raise ValueError("native evidence size limit")
            name = data[start:stop]
        else:
            name = b""
        if not typ & 0xe0:
            base = typ & 0x0e
            if base == 0x0a: raise ValueError("unsupported indirect symbol")
            if base not in (0, 2, 0x0c, 0x0e): raise ValueError("unsupported symbol type")
            if base == 0x0e:
                if not 1 <= sect <= len(sections): raise ValueError("invalid symbol section")
        symbols.append({"index": i, "string_index": strx, "name_base64": base64.b64encode(name).decode(),
                        "type": typ, "section": sect, "desc": desc, "value": f"{value:016x}"})
    return {"format": "macho64-le-symtab-v1", "cpu_type": cpu, "cpu_subtype": subtype,
            "file_type": file_type, "sections": sections, "symbols": symbols}


def same_json(actual, expected):
    # Equality alone would accept JSON booleans in integer fields.
    if type(actual) is not type(expected): return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(same_json(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(same_json(a, b) for a, b in zip(actual, expected))
    return actual == expected


def evidence(value, data, file_type):
    expected = macho_summary(data, file_type)
    if not same_json(value, expected): raise ValueError("native symbol evidence does not match bytes")
    return expected


def direct_code_symbols(summary):
    result = []
    for section in summary["sections"]:
        flags = section["flags"]
        if flags & 0x80000400 and not flags & 0x02000000 and flags & 0xff not in (0, 8):
            raise ValueError("unsupported instruction-bearing section")
    for symbol in summary["symbols"]:
        typ = symbol["type"]
        if typ & 0xe0 or typ & 0x0e != 0x0e: continue
        section = summary["sections"][symbol["section"] - 1]
        flags = section["flags"]
        if not flags & 0x80000400 or flags & 0x02000000: continue
        if flags & 0xff: continue
        address, size = int(section["address"], 16), int(section["size"], 16)
        value = int(symbol["value"], 16)
        if address <= value < address + size:
            result.append((base64.b64decode(symbol["name_base64"]), symbol))
    return result


def emission_identity(value):
    fields(value, "requested_symbol actual_llvm_symbol unit_name linkage origin specialization capture_descriptor displayed_source_location")
    for name in ("requested_symbol", "actual_llvm_symbol", "unit_name", "linkage"): text(value[name])
    anchor = checked_origin(value["origin"])
    if anchor != ("ProcLiteral", "arrow"): raise ValueError("invalid closure origin")
    specialization_identity(value["specialization"])
    capture = fields(value["capture_descriptor"], "proc_type is_closure environment")
    type_identity(capture["proc_type"])
    if capture["proc_type"]["kind"] != "Iyi::ProcInstanceType" or type(capture["is_closure"]) is not bool:
        raise ValueError("invalid closure capture")
    if capture["is_closure"]: capture_environment(capture["environment"])
    elif capture["environment"] is not None: raise ValueError("invalid non-closure environment")
    location = fields(value["displayed_source_location"], "file line column")
    text(location["file"]); number(location["line"]); number(location["column"])
    if not location["line"] or not location["column"]: raise ValueError("invalid source location")
    return (value["origin"], value["specialization"], capture, location)


class FrameManifest:
    def __init__(self, path, executable):
        with open(path, encoding="utf-8") as stream:
            manifest = json.load(stream, object_pairs_hook=no_duplicate_keys)
        fields(manifest, "schema object_input_scope executable_sha256 executable_symbols object_inputs bindings")
        if type(manifest["schema"]) is not int or manifest["schema"] != 5 or manifest["object_input_scope"] != "compiler_supplied_link_inputs":
            raise ValueError("unsupported manifest schema or scope")
        with open(executable, "rb") as stream: binary = stream.read()
        if hashlib.sha256(binary).hexdigest() != manifest["executable_sha256"]:
            raise ValueError("executable digest mismatch")
        linked = evidence(manifest["executable_symbols"], binary, 2)
        with open(executable, "rb") as stream:
            if stream.read() != binary: raise ValueError("executable changed while inspecting")
        if not linked["symbols"]: raise ValueError("empty executable symbols")
        inputs = manifest["object_inputs"]
        if not isinstance(inputs, list) or not inputs: raise ValueError("missing link inputs")
        seen, current_units, object_code = set(), {}, []
        for index, item in enumerate(inputs):
            fields(item, "link_input_id producer unit_name partition sha256 bytes_base64 native_evidence")
            if type(item["link_input_id"]) is not int or item["link_input_id"] != index: raise ValueError("invalid link input ID")
            text(item["unit_name"])
            producer = item["producer"]
            if not isinstance(producer, dict): raise ValueError("invalid producer")
            if producer.get("kind") == "current_unit":
                fields(producer, "kind unit_ordinal"); number(producer["unit_ordinal"])
            elif producer.get("kind") == "artifact_object":
                fields(producer, "kind artifact_identity object_ordinal")
                text(producer["artifact_identity"]); number(producer["object_ordinal"])
            else: raise ValueError("unknown producer")
            partition = item["partition"]
            if partition is not None:
                fields(partition, "index count"); number(partition["index"]); number(partition["count"])
                if partition["count"] == 0 or partition["index"] >= partition["count"]: raise ValueError("invalid partition")
            coordinate = json.dumps([producer, partition if producer["kind"] == "current_unit" else None], sort_keys=True, separators=(",", ":"))
            if coordinate in seen: raise ValueError("duplicate input coordinate")
            seen.add(coordinate)
            if producer["kind"] == "current_unit":
                group = current_units.setdefault(producer["unit_ordinal"], [])
                group.append((item["unit_name"], partition))
            try:
                data = base64.b64decode(item["bytes_base64"], validate=True)
            except (ValueError, TypeError) as exc: raise ValueError("invalid object encoding") from exc
            if base64.b64encode(data).decode("ascii") != item["bytes_base64"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("object digest mismatch")
            object_summary = evidence(item["native_evidence"], data, 1)
            if object_summary["cpu_type"] != linked["cpu_type"]: raise ValueError("inconsistent Mach-O architecture")
            object_code.append(direct_code_symbols(object_summary))
        for group in current_units.values():
            if len({name for name, _ in group}) != 1: raise ValueError("unit name collision")
            partitions = [part for _, part in group]
            if partitions == [None]: continue
            if any(part is None for part in partitions): raise ValueError("mixed partition coordinates")
            count = partitions[0]["count"]
            if any(part["count"] != count for part in partitions) or len(partitions) != count:
                raise ValueError("incomplete partition set")
        bindings = manifest["bindings"]
        if not isinstance(bindings, list): raise ValueError("missing object bindings")
        identities, requested_names, bound = {}, {}, set()
        for binding in bindings:
            fields(binding, "link_input_id definition")
            index = binding["link_input_id"]
            if type(index) is not int or not 0 <= index < len(inputs): raise ValueError("binding input absent")
            item = inputs[index]
            definition = fields(binding["definition"], "emission post_partition_llvm_symbol native_object_symbol post_partition_linkage partition_role")
            for name in ("post_partition_llvm_symbol", "native_object_symbol", "post_partition_linkage"): text(definition[name])
            role = definition["partition_role"]
            if role not in ("single", "owner", "local_copy") or (item["partition"] is None) != (role == "single"):
                raise ValueError("invalid partition role")
            llvm_name = definition["post_partition_llvm_symbol"]
            if llvm_name.startswith("\x01") or definition["native_object_symbol"] != "_" + llvm_name: raise ValueError("unsupported native decoration")
            name = definition["native_object_symbol"].encode("utf-8")
            if definition["emission"]["unit_name"] != item["unit_name"]: raise ValueError("binding unit mismatch")
            identity = emission_identity(definition["emission"])
            requested = definition["emission"]["requested_symbol"].encode("utf-8")
            matches = [s for n, s in object_code[index] if n == name]
            if len(matches) != 1: raise ValueError("binding absent or ambiguous in object")
            if matches[0]["desc"] & 0x300: raise ValueError("unsupported resolver or alternate entry")
            key = (index, name)
            if key in bound: raise ValueError("duplicate object binding")
            bound.add(key)
            if name in identities and identities[name] != identity: raise ValueError("ambiguous native symbol")
            requested_names.setdefault(name, []).append(requested)
            identities[name] = identity
        linked_text = direct_code_symbols(linked)
        linked_by_name, linked_by_address = {}, {}
        for name, symbol in linked_text:
            linked_by_name.setdefault(name, []).append(symbol)
            linked_by_address.setdefault((symbol["section"], symbol["value"]), []).append(name)
            if name.startswith((b"_~proc", b"_~fun_literal")) and name not in identities:
                raise ValueError("linked closure lacks provenance")
        linked_names = set(linked_by_name)
        for index, symbols in enumerate(object_code):
            for name, symbol in symbols:
                if name in identities and (index, name) not in bound:
                    raise ValueError("unbound competing definition")
        for name, identity in identities.items():
            matches = linked_by_name.get(name, [])
            if len(matches) > 1: raise ValueError("ambiguous executable definition")
            if not matches: continue
            symbol = matches[0]
            if symbol["desc"] & 0x300: raise ValueError("unsupported resolver or alternate entry")
            for other in linked_by_address[(symbol["section"], symbol["value"])]:
                if identities.get(other) != identity: raise ValueError("ambiguous folded symbol")
        self.identities = {name: identity for name, identity in identities.items() if name in linked_names}
        self.requested_names = {name: requested_names[name] for name in self.identities}

    def resolve(self, symbol):
        name = b"_" + symbol
        if name not in self.identities: raise ValueError("closure symbol missing from executable")
        originals = self.requested_names[name]
        shape = requested_shape(originals[0])
        if any(requested_shape(item) != shape for item in originals[1:]):
            raise ValueError("ambiguous original closure spelling")
        return self.identities[name], originals[0]


def requested_shape(symbol):
    prefix = re.match(rb"^~proc(\d*)Proc\(", symbol)
    location = proc_location(symbol)
    if not prefix or location is None: raise ValueError("unsupported original closure linkage")
    canonical = canonical_function(symbol)
    return canonical[:prefix.start(1)] + canonical[prefix.end(1):]


def compare_functions(left, right, manifests):
    if manifests is None: return canonical_function(left) == canonical_function(right)
    a, b = left.startswith((b"~proc", b"~fun_literal")), right.startswith((b"~proc", b"~fun_literal"))
    if not a and not b: return canonical_function(left) == canonical_function(right)
    if not a or not b: return False
    (identity_a, original_a), (identity_b, original_b) = manifests[0].resolve(left), manifests[1].resolve(right)
    if identity_a[:3] != identity_b[:3]: return False
    location_a, location_b = identity_a[3], identity_b[3]
    la, lb = proc_location(original_a), proc_location(original_b)
    if int(original_a[la[2]:la[3]]) != location_a["line"] or int(original_b[lb[2]:lb[3]]) != location_b["line"]:
        raise ValueError("closure line does not match emission")
    if (canonical_file(location_a["file"].encode()), location_a["line"], location_a["column"]) != (canonical_file(location_b["file"].encode()), location_b["line"], location_b["column"]): return False
    return requested_shape(original_a) == requested_shape(original_b)


def report_violation(line_no: int, rule: str, left: bytes, right: bytes):
    sys.stdout.write(f"line {line_no}: rule {rule}\n  left:  {repr(left)}\n  right: {repr(right)}\n")


def compare_same_opt(lines1: list[bytes], lines2: list[bytes], require_frames: bool = False, manifests=None) -> int:
    # Equal line count
    if len(lines1) != len(lines2):
        min_len = min(len(lines1), len(lines2))
        line_no = min_len + 1
        left = lines1[min_len] if len(lines1) > min_len else b''
        right = lines2[min_len] if len(lines2) > min_len else b''
        report_violation(line_no, 'line_count', left, right)
        return 1

    named_frames_found_1 = 0
    named_frames_found_2 = 0
    for idx, (l1, l2) in enumerate(zip(lines1, lines2)):
        line_no = idx + 1
        f1 = parse_frame(l1)
        f2 = parse_frame(l2)

        # Frame lines at the same positions
        if bool(f1) != bool(f2):
            report_violation(line_no, 'position', l1, l2)
            return 1

        # Non-frame lines byte-equal
        if not f1:
            if l1 != l2:
                report_violation(line_no, 'text', l1, l2)
                return 1
        else:
            kind1, kind2 = f1[0], f2[0]
            if kind1 != kind2:
                report_violation(line_no, 'position', l1, l2)
                return 1

            if kind1 == 'darwin':
                _, idx1, img1, fn1 = f1
                _, idx2, img2, fn2 = f2

                if idx1 != idx2:
                    report_violation(line_no, 'index', l1, l2)
                    return 1
                if img1 != img2:
                    report_violation(line_no, 'image', l1, l2)
                    return 1
                try:
                    matched = compare_functions(FRAME_RE.match(l1.rstrip(b'\r\n')).group(3), FRAME_RE.match(l2.rstrip(b'\r\n')).group(3), manifests)
                except ValueError as exc:
                    report_violation(line_no, 'provenance', str(exc).encode(), l2)
                    return 1
                if not matched:
                    report_violation(line_no, 'function', l1, l2)
                    return 1
                if is_named_function(fn1):
                    named_frames_found_1 += 1
                if is_named_function(fn2):
                    named_frames_found_2 += 1
            elif kind1 == 'linux':
                _, idx1, fn1, file1, line1, col1 = f1
                _, idx2, fn2, file2, line2, col2 = f2

                if idx1 != idx2:
                    report_violation(line_no, 'index', l1, l2)
                    return 1
                try:
                    matched = compare_functions(LINUX_FRAME_RE.match(l1.rstrip(b'\r\n')).group(2), LINUX_FRAME_RE.match(l2.rstrip(b'\r\n')).group(2), manifests)
                except ValueError as exc:
                    report_violation(line_no, 'provenance', str(exc).encode(), l2)
                    return 1
                if not matched:
                    report_violation(line_no, 'function', l1, l2)
                    return 1
                if (file1, line1, col1) != (file2, line2, col2):
                    report_violation(line_no, 'location', l1, l2)
                    return 1
                if is_named_function(fn1):
                    named_frames_found_1 += 1
                if is_named_function(fn2):
                    named_frames_found_2 += 1

    if require_frames and (named_frames_found_1 == 0 or named_frames_found_2 == 0):
        report_violation(1, 'zero_frames', lines1[0] if lines1 else b'', lines2[0] if lines2 else b'')
        return 1

    return 0


def compare_across_opt(lines1: list[bytes], lines2: list[bytes], require_frames: bool = False) -> int:
    def chunk_items(lines):
        items = []
        i = 0
        n = len(lines)
        while i < n:
            line_no = i + 1
            line = lines[i]
            f = parse_frame(line)
            if f:
                kind = f[0]
                frames = []
                while i < n:
                    cur_f = parse_frame(lines[i])
                    if cur_f and cur_f[0] == kind:
                        frames.append((lines[i], cur_f))
                        i += 1
                    else:
                        break
                items.append((kind, line_no, frames))
            else:
                items.append(('text', line_no, line))
                i += 1
        return items

    items1 = chunk_items(lines1)
    items2 = chunk_items(lines2)

    min_len = min(len(items1), len(items2))
    named_frames_found_1 = 0
    named_frames_found_2 = 0
    for i in range(min_len):
        k1, lno1, val1 = items1[i]
        k2, lno2, val2 = items2[i]

        if k1 != k2:
            left = val1 if k1 == 'text' else val1[0][0]
            right = val2 if k2 == 'text' else val2[0][0]
            report_violation(lno1, 'position', left, right)
            return 1

        if k1 == 'text':
            if val1 != val2:
                report_violation(lno1, 'text', val1, val2)
                return 1
        elif k1 == 'darwin':
            # Darwin legacy across-optimization semantics:
            # inlining changes frame counts and offsets; verify non-empty chunk
            if len(val1) == 0 or len(val2) == 0:
                left = val1[0][0] if val1 else b''
                right = val2[0][0] if val2 else b''
                report_violation(lno1, 'empty_frames', left, right)
                return 1
            for _, f in val1:
                if is_named_function(f[3]):
                    named_frames_found_1 += 1
            for _, f in val2:
                if is_named_function(f[3]):
                    named_frames_found_2 += 1
        elif k1 == 'linux':
            # Strict Linux across-optimization semantics:
            # preserve count, index, function, file, line, column, order
            if len(val1) != len(val2):
                min_flen = min(len(val1), len(val2))
                err_lno = lno1 + min_flen
                left = val1[min_flen][0] if len(val1) > min_flen else b''
                right = val2[min_flen][0] if len(val2) > min_flen else b''
                report_violation(err_lno, 'line_count', left, right)
                return 1

            for f_idx, ((raw1, f1), (raw2, f2)) in enumerate(zip(val1, val2)):
                frame_lno = lno1 + f_idx
                _, idx1, fn1, file1, line1, col1 = f1
                _, idx2, fn2, file2, line2, col2 = f2

                if idx1 != idx2:
                    report_violation(frame_lno, 'index', raw1, raw2)
                    return 1
                if fn1 != fn2:
                    report_violation(frame_lno, 'function', raw1, raw2)
                    return 1
                if (file1, line1, col1) != (file2, line2, col2):
                    report_violation(frame_lno, 'location', raw1, raw2)
                    return 1
                if is_named_function(fn1):
                    named_frames_found_1 += 1
                if is_named_function(fn2):
                    named_frames_found_2 += 1

    if len(items1) != len(items2):
        if len(items1) > len(items2):
            k, lno, val = items1[min_len]
            left = val if k == 'text' else val[0][0]
            right = b''
        else:
            k, lno, val = items2[min_len]
            left = b''
            right = val if k == 'text' else val[0][0]
        report_violation(lno, 'item_count', left, right)
        return 1

    if require_frames and (named_frames_found_1 == 0 or named_frames_found_2 == 0):
        report_violation(1, 'zero_frames', lines1[0] if lines1 else b'', lines2[0] if lines2 else b'')
        return 1

    return 0


def generate_mutant(kind: str, lines: list[bytes]) -> list[bytes]:
    mutated = list(lines)
    if kind == "text":
        for i, line in enumerate(mutated):
            if not is_frame(line):
                mutated[i] = b"MUTANT " + line
                return mutated
        raise ValueError("no text line to mutate")
    elif kind in ("drop", "count"):
        for i, line in enumerate(mutated):
            if is_frame(line):
                del mutated[i]
                return mutated
        if mutated:
            del mutated[0]
            return mutated
        raise ValueError("no line to drop")
    elif kind == "swap":
        for i in range(len(mutated) - 1):
            if is_frame(mutated[i]) and is_frame(mutated[i + 1]):
                mutated[i], mutated[i + 1] = mutated[i + 1], mutated[i]
                return mutated
        if len(mutated) >= 2:
            mutated[0], mutated[1] = mutated[1], mutated[0]
            return mutated
        raise ValueError("not enough lines to swap")
    elif kind == "position":
        for i in range(len(mutated) - 1):
            f1 = is_frame(mutated[i])
            f2 = is_frame(mutated[i + 1])
            if f1 != f2:
                mutated[i], mutated[i + 1] = mutated[i + 1], mutated[i]
                return mutated
        if mutated:
            if is_frame(mutated[0]):
                mutated.insert(0, b"nonframe text line\n")
            else:
                mutated.insert(0, b"0   frame_fn at /path/probe.iyi:1:1\n")
            return mutated
        raise ValueError("no line to mutate for position")
    elif kind == "function":
        for i, line in enumerate(mutated):
            s = line.rstrip(b'\r\n')
            m_d = FRAME_RE.match(s)
            m_l = LINUX_FRAME_RE.match(s)
            if m_d:
                fn = m_d.group(3)
                new_fn = b"mutant_" + fn
                mutated[i] = line.replace(fn, new_fn, 1)
                return mutated
            elif m_l:
                fn = m_l.group(2)
                new_fn = b"mutant_" + fn
                mutated[i] = line.replace(fn, new_fn, 1)
                return mutated
        raise ValueError("no frame line for function mutant")
    elif kind == "index":
        for i, line in enumerate(mutated):
            s = line.rstrip(b'\r\n')
            m_d = FRAME_RE.match(s)
            m_l = LINUX_FRAME_RE.match(s)
            if m_d or m_l:
                idx = (m_d or m_l).group(1)
                new_idx = str(int(idx) + 99).encode()
                mutated[i] = re.sub(rb'^\d+', new_idx, line, count=1)
                return mutated
        raise ValueError("no frame line for index mutant")
    elif kind == "image":
        for i, line in enumerate(mutated):
            m = FRAME_RE.match(line.rstrip(b'\r\n'))
            if m:
                img = m.group(2)
                new_img = b"mutant_image"
                mutated[i] = line.replace(img, new_img, 1)
                return mutated
        raise ValueError("no frame line for image mutant")
    elif kind in ("location", "line"):
        for i, line in enumerate(mutated):
            s = line.rstrip(b'\r\n')
            m_l = LINUX_FRAME_RE.match(s)
            if m_l:
                old_line = m_l.group(4)
                new_line = str(int(old_line) + 12345).encode()
                old_loc = m_l.group(3) + b':' + old_line + b':' + m_l.group(5)
                new_loc = m_l.group(3) + b':' + new_line + b':' + m_l.group(5)
                mutated[i] = line.replace(old_loc, new_loc, 1)
                return mutated
            m_d = FRAME_RE.match(s)
            if m_d:
                fn = m_d.group(3)
                loc = proc_location(fn)
                sub_m = re.fullmatch(rb'~proc\d*@[^@:]+:(\d+)', fn) if not loc else None
                if loc or sub_m:
                    start, end = (loc[2], loc[3]) if loc else sub_m.span(1)
                    old_num = fn[start:end]
                    new_num = str(int(old_num) + 12345).encode()
                    new_fn = fn[:start] + new_num + fn[end:]
                    mutated[i] = line.replace(fn, new_fn, 1)
                    return mutated
        raise ValueError("no frame line with location/line for mutant")
    elif kind == "column":
        for i, line in enumerate(mutated):
            s = line.rstrip(b'\r\n')
            m_l = LINUX_FRAME_RE.match(s)
            if m_l:
                old_col = m_l.group(5)
                new_col = str(int(old_col) + 54321).encode()
                old_loc = m_l.group(3) + b':' + m_l.group(4) + b':' + old_col
                new_loc = m_l.group(3) + b':' + m_l.group(4) + b':' + new_col
                mutated[i] = line.replace(old_loc, new_loc, 1)
                return mutated
        raise ValueError("no frame line with column for mutant")
    elif kind == "file":
        for i, line in enumerate(mutated):
            s = line.rstrip(b'\r\n')
            m_l = LINUX_FRAME_RE.match(s)
            if m_l:
                old_file = m_l.group(3)
                new_file = old_file + b'_mutant'
                old_loc = old_file + b':' + m_l.group(4) + b':' + m_l.group(5)
                new_loc = new_file + b':' + m_l.group(4) + b':' + m_l.group(5)
                mutated[i] = line.replace(old_loc, new_loc, 1)
                return mutated
        raise ValueError("no frame line with file for mutant")
    elif kind == "module":
        # change std/X to std/Y in a recognized frame
        for i, line in enumerate(mutated):
            s = line.rstrip(b'\r\n')
            m_d = FRAME_RE.match(s)
            if m_d:
                fn = m_d.group(3)
                if b'std/' in fn:
                    new_fn = re.sub(rb'std/([a-zA-Z0-9_]+)', rb'std/mutant_mod', fn, count=1)
                    if new_fn != fn:
                        mutated[i] = line.replace(fn, new_fn, 1)
                        return mutated
            m_l = LINUX_FRAME_RE.match(s)
            if m_l:
                file_part = m_l.group(3)
                if b'std/' in file_part:
                    new_file = re.sub(rb'std/([a-zA-Z0-9_]+)', rb'std/mutant_mod', file_part, count=1)
                    if new_file != file_part:
                        mutated[i] = line.replace(file_part, new_file, 1)
                        return mutated
                fn_part = m_l.group(2)
                if b'std/' in fn_part:
                    new_fn = re.sub(rb'std/([a-zA-Z0-9_]+)', rb'std/mutant_mod', fn_part, count=1)
                    if new_fn != fn_part:
                        mutated[i] = line.replace(fn_part, new_fn, 1)
                        return mutated
        raise ValueError("no frame line with std/ for module mutant")
    else:
        raise ValueError(f"unknown mutant kind: {kind}")


def main():
    args = sys.argv[1:]
    if not args:
        sys.stderr.write("Usage: frames_equivalent.py [--across-optimisation] [--require-frames] OUT_A OUT_B\n       frames_equivalent.py --mutant KIND OUT\n")
        sys.exit(2)

    if args[0] in ("--test", "--selftest"):
        from test_frames_equivalent import run_all_tests
        sys.exit(run_all_tests())

    if args[0] == "--mutant":
        if len(args) != 3:
            sys.stderr.write("Error: --mutant requires KIND and OUT\n")
            sys.exit(2)
        kind = args[1]
        out_path = args[2]
        try:
            with open(out_path, 'rb') as f:
                lines = f.readlines()
        except Exception as e:
            sys.stderr.write(f"Error reading {out_path}: {e}\n")
            sys.exit(2)
        try:
            mutated = generate_mutant(kind, lines)
        except Exception as e:
            sys.stderr.write(f"Error generating mutant: {e}\n")
            sys.exit(2)
        sys.stdout.buffer.write(b''.join(mutated))
        sys.exit(0)

    across_opt = False
    require_frames = False
    strict = False
    options = {}
    option_names = {"--source-manifest", "--artifact-manifest", "--source-executable", "--artifact-executable",
                    "--capture-authority", "--capture-authority-sha256"}
    files = []
    iterator = iter(args)
    for arg in iterator:
        if arg in ("--across-optimisation", "--across-optimization"):
            across_opt = True
        elif arg == "--strict-provenance":
            strict = True
        elif arg in option_names:
            if arg in options:
                sys.stderr.write(f"Duplicate option: {arg}\n")
                sys.exit(2)
            value = next(iterator, None)
            if value is None or value.startswith("-"):
                sys.stderr.write(f"Missing value for {arg}\n")
                sys.exit(2)
            options[arg] = value
        elif arg in ("--require-frames", "--require-named-frames", "--named-frame-proof"):
            require_frames = True
        elif arg.startswith("-"):
            sys.stderr.write(f"Unknown option: {arg}\n")
            sys.exit(2)
        else:
            files.append(arg)

    if len(files) != 2:
        sys.stderr.write("Error: exactly two files required\n")
        sys.exit(2)
    if (strict and (across_opt or set(options) != option_names)) or (not strict and options):
        sys.stderr.write("Error: strict provenance requires both manifests, executables, and independently pinned capture authority; across-optimisation is forbidden\n")
        sys.exit(2)
    manifests = None
    if strict:
        try:
            read_capture_authority(options["--capture-authority"], options["--capture-authority-sha256"])
            manifests = (FrameManifest(options["--source-manifest"], options["--source-executable"]),
                         FrameManifest(options["--artifact-manifest"], options["--artifact-executable"]))
            raise ValueError("capture authority resolver is not integrated")
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            sys.stderr.write(f"Invalid frame provenance: {exc}\n")
            sys.exit(1)

    try:
        with open(files[0], 'rb') as f1, open(files[1], 'rb') as f2:
            lines1 = f1.readlines()
            lines2 = f2.readlines()
    except Exception as e:
        sys.stderr.write(f"Error reading inputs: {e}\n")
        sys.exit(2)

    if across_opt:
        ret = compare_across_opt(lines1, lines2, require_frames=require_frames)
    else:
        ret = compare_same_opt(lines1, lines2, require_frames=require_frames, manifests=manifests)

    sys.exit(ret)

if __name__ == "__main__":
    main()
