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
import subprocess
import tempfile
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
        return ("Synthetic", value["synthesis_kind"])
    elif kind == "Expanded":
        fields(value, "kind invocation_origin macro_definition_origin expansion_guard generated_byte_offset anchor_kind role emission_parts spliced_origin")
        invocation = origin(value["invocation_origin"], depth + 1)
        definition = origin(value["macro_definition_origin"], depth + 1)
        if invocation not in (("Call", "method"), ("MacroDirective", "expression"), ("MacroDirective", "control")) or definition != ("Macro", "keyword"):
            raise ValueError("invalid macro ancestry")
        if not isinstance(value["expansion_guard"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["expansion_guard"]):
            raise ValueError("invalid expansion guard")
        number(value["generated_byte_offset"])
        parts = value["emission_parts"]
        if not isinstance(parts, list) or not parts: raise ValueError("missing emission parts")
        end, previous = value["generated_byte_offset"], object()
        for part in parts:
            fields(part, "start_offset end_offset emitter_origin")
            number(part["start_offset"]); number(part["end_offset"])
            emitter = part["emitter_origin"]
            if part["start_offset"] != end or part["end_offset"] <= end or emitter == previous:
                raise ValueError("invalid emission part")
            if emitter is not None and origin(emitter, depth + 1) not in (("MacroDirective", "expression"), ("MacroDirective", "control")):
                raise ValueError("invalid emitter")
            end, previous = part["end_offset"], emitter
        splice = value["spliced_origin"]
        if splice is not None and origin(splice, depth + 1) != (value["anchor_kind"], value["role"]):
            raise ValueError("invalid spliced origin")
    else:
        raise ValueError("unknown origin")
    text(value["anchor_kind"]); text(value["role"])
    return value["anchor_kind"], value["role"]


def checked_origin(value):
    # Bound the unfolded structure before recursive validation or equality.
    stack, size = [(value, 0)], 0
    while stack:
        node, depth = stack.pop()
        if depth > 260: raise ValueError("origin nesting too deep")
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
    return origin(value)


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


def native_symbols(raw):
    text_symbols = []
    for line in raw.splitlines():
        if not line: continue
        match = re.fullmatch(r"([0-9a-fA-F]+)\s+\(([^()]*)\)\s+((?:weak\s+)?(?:private\s+)?external|non-external)\s+(.+)", line)
        if not match or " (was a private external)" in match.group(4):
            raise ValueError("unsupported native symbol evidence")
        text_symbols.append({"address": match.group(1), "kind": match.group(2) + " " + match.group(3), "name": match.group(4)})
    return text_symbols


def inspect_native(path):
    try:
        result = subprocess.run(["nm", "-m", "-U", path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode("utf-8")
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        raise ValueError("cannot inspect native symbols") from exc


def evidence(value, path):
    fields(value, "raw_nm symbols")
    if not isinstance(value["raw_nm"], str) or not isinstance(value["symbols"], list):
        raise ValueError("invalid symbol evidence")
    if native_symbols(value["raw_nm"]) != value["symbols"]:
        raise ValueError("recorded symbol evidence mismatch")
    if inspect_native(path) != value["raw_nm"]:
        raise ValueError("native symbol evidence does not match bytes")
    return value["symbols"]


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
        if type(manifest["schema"]) is not int or manifest["schema"] != 3 or manifest["object_input_scope"] != "compiler_supplied_link_inputs":
            raise ValueError("unsupported manifest schema or scope")
        with open(executable, "rb") as stream: binary = stream.read()
        if hashlib.sha256(binary).hexdigest() != manifest["executable_sha256"]:
            raise ValueError("executable digest mismatch")
        linked = evidence(manifest["executable_symbols"], executable)
        with open(executable, "rb") as stream:
            if stream.read() != binary: raise ValueError("executable changed while inspecting")
        if not linked: raise ValueError("empty executable symbols")
        inputs = manifest["object_inputs"]
        if not isinstance(inputs, list) or not inputs: raise ValueError("missing link inputs")
        seen, current_units = set(), {}
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
            with tempfile.NamedTemporaryFile() as obj:
                obj.write(data); obj.flush()
                evidence(item["native_evidence"], obj.name)
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
        identities, bound = {}, set()
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
            name = definition["native_object_symbol"]
            llvm_name = definition["post_partition_llvm_symbol"]
            if llvm_name.startswith("\x01") or name != "_" + llvm_name: raise ValueError("unsupported native decoration")
            if definition["emission"]["unit_name"] != item["unit_name"]: raise ValueError("binding unit mismatch")
            identity = emission_identity(definition["emission"])
            symbols = item["native_evidence"]["symbols"]
            if not any(s["name"] == name and s["kind"].startswith("__TEXT,__text ") for s in symbols):
                raise ValueError("binding absent from object")
            key = (index, name)
            if key in bound: raise ValueError("duplicate object binding")
            bound.add(key)
            if name in identities and identities[name] != identity: raise ValueError("ambiguous native symbol")
            identities[name] = identity
        linked_text = [s for s in linked if s["kind"].startswith("__TEXT,__text ")]
        linked_names = {s["name"] for s in linked_text}
        for symbol in linked_text:
            if symbol["name"].startswith(("_~proc", "_~fun_literal")) and symbol["name"] not in identities:
                raise ValueError("linked closure lacks provenance")
        for item in inputs:
            for symbol in item["native_evidence"]["symbols"]:
                if symbol["kind"].startswith("__TEXT,__text ") and symbol["name"] in identities and symbol["name"] in linked_names and (item["link_input_id"], symbol["name"]) not in bound:
                    raise ValueError("unbound competing definition")
        for symbol in linked_text:
            if symbol["name"] in identities:
                for other in linked_text:
                    if int(other["address"], 16) == int(symbol["address"], 16) and identities.get(other["name"]) != identities[symbol["name"]]:
                        raise ValueError("ambiguous folded symbol")
        self.identities = {name: identity for name, identity in identities.items() if name in linked_names}

    def resolve(self, symbol):
        try: name = "_" + symbol.decode("utf-8")
        except UnicodeError as exc: raise ValueError("invalid symbol encoding") from exc
        if name not in self.identities: raise ValueError("closure symbol missing from executable")
        return self.identities[name]


def compare_functions(left, right, manifests):
    if manifests is None: return canonical_function(left) == canonical_function(right)
    a, b = left.startswith((b"~proc", b"~fun_literal")), right.startswith((b"~proc", b"~fun_literal"))
    if not a and not b: return canonical_function(left) == canonical_function(right)
    if not a or not b: return False
    pa, pb = re.match(rb"^~proc(\d*)Proc\(", left), re.match(rb"^~proc(\d*)Proc\(", right)
    if not pa or not pb or proc_location(left) is None or proc_location(right) is None:
        raise ValueError("unsupported closure linkage")
    identity_a, identity_b = manifests[0].resolve(left), manifests[1].resolve(right)
    if identity_a[:3] != identity_b[:3]: return False
    location_a, location_b = identity_a[3], identity_b[3]
    la, lb = proc_location(left), proc_location(right)
    if int(left[la[2]:la[3]]) != location_a["line"] or int(right[lb[2]:lb[3]]) != location_b["line"]:
        raise ValueError("closure line does not match emission")
    if (canonical_file(location_a["file"].encode()), location_a["line"], location_a["column"]) != (canonical_file(location_b["file"].encode()), location_b["line"], location_b["column"]): return False
    ca, cb = canonical_function(left), canonical_function(right)
    return ca[:pa.start(1)] + ca[pa.end(1):] == cb[:pb.start(1)] + cb[pb.end(1):]


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
    option_names = {"--source-manifest", "--artifact-manifest", "--source-executable", "--artifact-executable"}
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
        sys.stderr.write("Error: strict provenance requires both manifests and executables and forbids across-optimisation\n")
        sys.exit(2)
    manifests = None
    if strict:
        try:
            manifests = (FrameManifest(options["--source-manifest"], options["--source-executable"]),
                         FrameManifest(options["--artifact-manifest"], options["--artifact-executable"]))
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
