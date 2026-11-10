#!/usr/bin/env python3
"""Behavioral tests for bench/verify_capture_frames.py. Standard library only.

Each negative test asserts the specific error code the verifier must raise.
Streams are built here from a synthetic schema in the DiagnosticFieldTable::Row
shape. The class-to-role literal below is written out independently of the
verifier so a mismatch with role_for fails a test rather than hiding in both.
"""

import base64
import contextlib
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
if BENCH_DIR not in sys.path:
    sys.path.insert(0, BENCH_DIR)

import verify_capture_frames as vcf  # noqa: E402
from verify_capture_frames import VerifyError, load_schema, verify_capture_stream  # noqa: E402

TAG_N = ord("N")
TAG_F = ord("F")
TAG_A = ord("A")

# role_for in src/compiler/iyi/syntax/diagnostic_field_table.cr, written out for all ten classes.
ROLE_FOR_TABLE = {
    "Child": "Child",
    "ChildList": "Child",
    "NamedChildMap": "Child",
    "IndexedChildMap": "Child",
    "Record": "Child",
    "RecordList": "Child",
    "NamedValue": "Name",
    "SyntaxScalar": "Scalar",
    "OriginEvidence": "Evidence",
    "Infrastructure": "Infrastructure",
}


def b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def frame(tag, payload):
    return bytes([tag]) + len(payload).to_bytes(8, "big") + payload


def alias(owner):
    return bytes([TAG_A]) + owner.to_bytes(8, "big")


def dumps(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def snapshot(name):
    return dumps({"kind": "file", "path": name})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stream_digest(stream):
    return hashlib.sha256(vcf.DIGEST_TAG + stream).hexdigest()


def srow(field, klass, *, coordinate="Single", presence="Always", nilable=False, scalar=None,
         type_expression=None, provenance="Syntax", base=False):
    return {
        "field": field,
        "klass": klass,
        "role": ROLE_FOR_TABLE[klass],
        "coordinate": coordinate,
        "presence": presence,
        "nilable": nilable,
        "scalar": scalar,
        "provenance": provenance,
        "base": base,
        "type_expression": type_expression,
    }


SCHEMA = {
    "schema": "iyi-field-schema/1",
    "kinds": {
        "Program": [
            srow("flag", "SyntaxScalar", presence="Always", nilable=False, scalar="bool", type_expression="Bool"),
            srow("count", "SyntaxScalar", presence="Optional", nilable=True, scalar="int32?", type_expression="Int32"),
            srow("location", "OriginEvidence", presence="Optional", nilable=True, type_expression="String"),
            srow("label", "NamedValue", presence="Optional", nilable=True, type_expression="String"),
            srow("body", "ChildList", coordinate="Indexed", presence="Collection", nilable=False, type_expression="Node"),
            srow("dirty", "Infrastructure", presence=None, nilable=None, base=True),
        ],
        "Pair": [
            srow("items", "ChildList", coordinate="Indexed", presence="Collection", nilable=False, type_expression="Node"),
        ],
        "Leaf": [
            srow("value", "SyntaxScalar", presence="Always", nilable=False, scalar="bytes", type_expression="String"),
            srow("location", "OriginEvidence", presence="Optional", nilable=True, type_expression="String"),
        ],
        "Map": [
            srow("entries", "IndexedChildMap", coordinate="Indexed", presence="Collection", nilable=False,
                 type_expression="Node"),
        ],
        "Keyed": [
            srow("entries", "NamedChildMap", coordinate="Keyed", presence="Collection", nilable=False,
                 type_expression="Node"),
        ],
    },
}


def schema_doc():
    return copy.deepcopy(SCHEMA)


SCHEMA_OBJ = load_schema(schema_doc())


class Node:
    """A synthetic node. scalars: (field, value). names: (field, index, key, text).
    children: (field, index, key, child). Index is set only for Indexed rows and key only for
    Keyed rows; Single rows take None for both."""

    def __init__(self, kind, *, scalars=(), names=(), children=(), filename=None, line=1):
        self.kind = kind
        self.scalars = list(scalars)
        self.names = list(names)
        self.children = list(children)
        self.filename = filename
        self.line = line


def framed_rows(kind):
    return [r for r in SCHEMA["kinds"][kind] if not r["base"] and r["role"] != "Infrastructure"]


def derive_state(node, row):
    role, field = row["role"], row["field"]
    if role == "Scalar":
        value = next((v for f, v in node.scalars if f == field), None)
        if row["presence"] == "Always":
            return "Present"
        return "Present" if value is not None else "Absent"
    if role == "Evidence":
        return "Present" if node.filename is not None else "Absent"
    has = (any(f == field for f, _i, _k, _c in node.children)
           or any(f == field for f, _i, _k, _t in node.names))
    if row["presence"] == "Always":
        return "Present"
    if row["presence"] == "Optional":
        return "Present" if has else "Absent"
    return "Nonempty" if has else "Empty"


def encode_scalar(tag, value):
    if value is None:
        return None
    base = tag[:-1] if tag.endswith("?") else tag
    if base == "bytes":
        return b64(value)
    return value


def node_dict(owner, node):
    location = None
    if node.filename is not None:
        location = {
            "filename_sha256": sha(snapshot(node.filename)),
            "line": node.line,
            "column": 1,
            "artifact": None,
        }
    scalars = []
    for row in framed_rows(node.kind):
        if row["role"] != "Scalar":
            continue
        value = next((v for f, v in node.scalars if f == row["field"]), None)
        scalars.append({"field": row["field"], "type": row["scalar"], "value": encode_scalar(row["scalar"], value)})
    return {
        "owner_id": owner,
        "kind": node.kind,
        "presence": [{"field": r["field"], "state": derive_state(node, r)} for r in framed_rows(node.kind)],
        "scalars": scalars,
        "location": location,
        "end_location": None,
        "extra_locations": [],
        "origin": None,
        "macro_lineage": "",
        "external_name_explicit": False,
        "name_slots": [],
        "literal_names": [],
        "literal_productions": [],
        "names": [
            {"field": f, "index": i, "map_key_base64": None if k is None else b64(k), "value_base64": b64(text)}
            for f, i, k, text in node.names
        ],
        "children": [
            {"field": f, "index": i, "map_key_base64": None if k is None else b64(k), "node": {"kind": c.kind}}
            for f, i, k, c in node.children
        ],
    }


def encode_frames(root, *, filename_payloads=None):
    """Preorder encoder that mirrors the writer: F before first reference, A for revisits."""
    payloads = filename_payloads or {}
    frames = []
    owners = {}
    emitted = set()

    def visit(node):
        owner = len(owners)
        owners[id(node)] = owner
        if node.filename is not None and node.filename not in emitted:
            emitted.add(node.filename)
            frames.append(frame(TAG_F, payloads.get(node.filename, snapshot(node.filename))))
        frames.append(frame(TAG_N, dumps(node_dict(owner, node))))
        for _field, _index, _key, child in node.children:
            if id(child) in owners:
                frames.append(alias(owners[id(child)]))
            else:
                visit(child)

    visit(root)
    return b"".join(frames)


def build_positive(value="x"):
    leaf_x = Node("Leaf", scalars=[("value", value)], filename="main.iyi")
    leaf_y = Node("Leaf", scalars=[("value", "y")])
    pair = Node("Pair", children=[("items", 0, None, leaf_x), ("items", 1, None, leaf_y)])
    return Node(
        "Program",
        scalars=[("flag", True)],
        names=[("label", None, None, "main")],
        children=[("body", 0, None, pair), ("body", 1, None, leaf_x)],
        filename="main.iyi",
    )


def program_stub(children=(), *, filename=None):
    return Node("Program", scalars=[("flag", True)], children=list(children), filename=filename)


def verify(stream, expected, schema=None):
    return verify_capture_stream(
        io.BytesIO(stream),
        expected_sha256=expected,
        schema=SCHEMA_OBJ if schema is None else schema,
    )


class RecordingStream(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.requests = []

    def read(self, size=-1):
        self.requests.append(size)
        return super().read(size)


class VerifyCaptureFramesTest(unittest.TestCase):

    def assertRejects(self, code, stream, expected=None, schema=None):
        if expected is None:
            expected = stream_digest(stream)
        with self.assertRaises(VerifyError) as ctx:
            verify(stream, expected, schema)
        self.assertEqual(ctx.exception.code, code, str(ctx.exception))

    def assertSchemaRejects(self, code, doc):
        with self.assertRaises(VerifyError) as ctx:
            load_schema(doc)
        self.assertEqual(ctx.exception.code, code, str(ctx.exception))

    # Class table and positive

    def test_klass_roles_match_role_for_for_all_ten_classes(self):
        self.assertEqual(len(ROLE_FOR_TABLE), 10)
        self.assertEqual(set(vcf.KLASS_ROLE), set(ROLE_FOR_TABLE))
        for klass, role in ROLE_FOR_TABLE.items():
            with self.subTest(klass=klass):
                self.assertEqual(vcf.KLASS_ROLE[klass], role)

    def test_indexed_child_map_is_indexed_not_keyed(self):
        doc = schema_doc()
        doc["kinds"]["Map"][0]["coordinate"] = "Keyed"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_named_child_map_is_keyed_not_indexed(self):
        doc = schema_doc()
        doc["kinds"]["Keyed"][0]["coordinate"] = "Indexed"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_positive_stream_verifies(self):
        stream = encode_frames(build_positive())
        summary = verify(stream, stream_digest(stream))
        self.assertEqual(summary.sha256, stream_digest(stream))
        self.assertEqual(summary.nodes, 4)
        self.assertEqual(summary.aliases, 1)
        self.assertEqual(summary.filename_frames, 1)
        self.assertEqual(summary.stream_bytes, len(stream))
        self.assertEqual(summary.max_depth, 2)

    def test_positive_keyed_child_map_verifies(self):
        keyed = Node(
            "Keyed",
            children=[("entries", None, "a", Node("Leaf", scalars=[("value", "x")])),
                      ("entries", None, "b", Node("Leaf", scalars=[("value", "y")]))],
            names=[("entries.key", None, "a", "a"), ("entries.key", None, "b", "b")],
        )
        stream = encode_frames(keyed)
        self.assertEqual(verify(stream, stream_digest(stream)).nodes, 3)

    def test_reads_are_bounded_by_requested_size(self):
        stream = encode_frames(build_positive())
        recorder = RecordingStream(stream)
        verify_capture_stream(recorder, expected_sha256=stream_digest(stream), schema=SCHEMA_OBJ)
        self.assertTrue(recorder.requests)
        for size in recorder.requests:
            self.assertGreater(size, 0)
            self.assertLessEqual(size, vcf.READ_CHUNK_BYTES)

    def test_changed_value_with_rehashed_stream_fails_the_original_pin(self):
        original = encode_frames(build_positive("x"))
        changed = encode_frames(build_positive("z"))
        self.assertNotEqual(stream_digest(original), stream_digest(changed))
        with self.assertRaises(VerifyError) as ctx:
            verify(changed, stream_digest(original))
        self.assertEqual(ctx.exception.code, "digest_mismatch")
        self.assertEqual(verify(changed, stream_digest(changed)).sha256, stream_digest(changed))

    def test_unpinned_stream_is_refused_before_reading(self):
        stream = encode_frames(build_positive())
        for expected in (None, "", "ABC", "A" * 64, "a" * 63):
            with self.subTest(expected=expected):
                with self.assertRaises(VerifyError) as ctx:
                    verify(stream, expected)
                self.assertEqual(ctx.exception.code, "unpinned_stream")

    def test_wrong_pin_is_digest_mismatch(self):
        self.assertRejects("digest_mismatch", encode_frames(build_positive()), expected="0" * 64)

    def test_null_type_expression_issues_no_verdict(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["type_expression"] = None
        stream = encode_frames(build_positive())
        self.assertRejects("unproven_type_expression", stream, schema=load_schema(doc))

    # Framing

    def test_empty_stream(self):
        self.assertRejects("empty_stream", b"")

    def test_truncated_header(self):
        self.assertRejects("truncated", encode_frames(build_positive())[:5])

    def test_truncated_payload(self):
        stream = frame(TAG_N, dumps(node_dict(0, program_stub())))
        self.assertRejects("truncated", stream[:-3])

    def test_truncated_trailing_alias(self):
        self.assertRejects("truncated", encode_frames(build_positive())[:-1])

    def test_trailing_valid_frame_after_root(self):
        self.assertRejects("trailing_data", encode_frames(build_positive()) + alias(0))

    def test_trailing_partial_header(self):
        self.assertRejects("truncated", encode_frames(build_positive()) + b"\x41\x00\x00")

    def test_unknown_tag(self):
        self.assertRejects("unknown_frame", b"X" + (0).to_bytes(8, "big"))

    def test_frame_length_over_limit(self):
        self.assertRejects("frame_too_large", bytes([TAG_N]) + (vcf.MAX_FRAME_BYTES + 1).to_bytes(8, "big"))

    def test_frame_length_longer_than_stream(self):
        self.assertRejects("truncated", bytes([TAG_N]) + (100).to_bytes(8, "big") + b"0123456789")

    def test_frame_length_shorter_than_json(self):
        payload = dumps(node_dict(0, program_stub()))
        self.assertRejects("malformed_json", bytes([TAG_N]) + (5).to_bytes(8, "big") + payload)

    def test_input_budget(self):
        with mock.patch.object(vcf, "MAX_INPUT_BYTES", 40):
            self.assertRejects("input_budget", encode_frames(build_positive()))

    def test_index_budget(self):
        with mock.patch.object(vcf, "MAX_INDEX_BYTES", 10):
            self.assertRejects("index_budget", encode_frames(build_positive()))

    # JSON

    def test_duplicate_json_key(self):
        payload = dumps(node_dict(0, program_stub()))
        duplicated = payload.replace(b'"owner_id":0', b'"owner_id":0,"owner_id":0', 1)
        self.assertRejects("duplicate_key", frame(TAG_N, duplicated))

    def test_float_value_rejected(self):
        node = Node("Leaf", scalars=[("value", "x")])
        payload = dumps(node_dict(0, node))
        self.assertIn(b'"value":"eA=="}', payload)
        self.assertRejects("float_number", frame(TAG_N, payload.replace(b'"value":"eA=="}', b'"value":1.0}')))

    def test_nonfinite_value_rejected(self):
        node = Node("Program", scalars=[("flag", True), ("count", 7)])
        payload = dumps(node_dict(0, node))
        self.assertIn(b'"value":7}', payload)
        self.assertRejects("nonfinite_number", frame(TAG_N, payload.replace(b'"value":7}', b'"value":NaN}')))

    def test_invalid_utf8_is_malformed(self):
        self.assertRejects("malformed_json", frame(TAG_N, b'{"owner_id":\xff}'))

    def test_json_depth_limit(self):
        n = vcf.MAX_JSON_NESTING + 1
        self.assertRejects("depth_exceeded", frame(TAG_N, b"[" * n + b"]" * n))

    # Owners, aliases and the tree

    def test_owner_id_must_be_contiguous(self):
        root = program_stub([("body", 0, None, Node("Pair"))])
        stream = frame(TAG_N, dumps(node_dict(0, root))) + frame(TAG_N, dumps(node_dict(5, Node("Pair"))))
        self.assertRejects("owner_id_mismatch", stream)

    def test_alias_forward(self):
        root = program_stub([("body", 0, None, Node("Leaf"))])
        self.assertRejects("alias_forward", frame(TAG_N, dumps(node_dict(0, root))) + alias(5))

    def test_alias_cycle_to_active_ancestor(self):
        root = program_stub([("body", 0, None, Node("Program"))])
        self.assertRejects("alias_cycle", frame(TAG_N, dumps(node_dict(0, root))) + alias(0))

    def test_alias_kind_mismatch(self):
        root = program_stub([("body", 0, None, Node("Pair")), ("body", 1, None, Node("Leaf"))])
        stream = (
            frame(TAG_N, dumps(node_dict(0, root)))
            + frame(TAG_N, dumps(node_dict(1, Node("Pair"))))
            + alias(1)
        )
        self.assertRejects("kind_mismatch", stream)

    def test_subtree_kind_mismatch_against_stub(self):
        root = program_stub([("body", 0, None, Node("Leaf"))])
        stream = frame(TAG_N, dumps(node_dict(0, root))) + frame(TAG_N, dumps(node_dict(1, Node("Pair"))))
        self.assertRejects("kind_mismatch", stream)

    def test_missing_child_frame_at_end_of_stream(self):
        pair = Node("Pair", children=[("items", 0, None, Node("Leaf", scalars=[("value", "a")]))])
        root = program_stub([("body", 0, None, pair)])
        stream = frame(TAG_N, dumps(node_dict(0, root))) + frame(TAG_N, dumps(node_dict(1, pair)))
        self.assertRejects("missing_frame", stream)

    def test_unknown_root_kind(self):
        node = node_dict(0, Node("Leaf"))
        node["kind"] = "Mystery"
        self.assertRejects("unknown_kind", frame(TAG_N, dumps(node)))

    def test_unknown_child_stub_kind(self):
        root = program_stub([("body", 0, None, Node("Mystery"))])
        self.assertRejects("unknown_kind", frame(TAG_N, dumps(node_dict(0, root))))

    def test_depth_limit_accepts_128_and_rejects_129(self):
        def chain(levels):
            node = Node("Leaf", scalars=[("value", "x")])
            for _ in range(levels):
                node = Node("Pair", children=[("items", 0, None, node)])
            return node

        ok = encode_frames(chain(128))
        self.assertEqual(verify(ok, stream_digest(ok)).max_depth, 128)
        self.assertRejects("depth_exceeded", encode_frames(chain(129)))

    # Child and name stubs

    def test_indexed_child_gap_is_stub_index(self):
        pair = Node("Pair", children=[
            ("items", 0, None, Node("Leaf", scalars=[("value", "a")])),
            ("items", 2, None, Node("Leaf", scalars=[("value", "b")])),
        ])
        self.assertRejects("stub_index", frame(TAG_N, dumps(node_dict(0, pair))))

    def test_indexed_child_repeat_is_stub_index(self):
        pair = Node("Pair", children=[
            ("items", 0, None, Node("Leaf", scalars=[("value", "a")])),
            ("items", 0, None, Node("Leaf", scalars=[("value", "a")])),
        ])
        self.assertRejects("stub_index", frame(TAG_N, dumps(node_dict(0, pair))))

    def test_indexed_child_without_index_is_stub_coordinate(self):
        pair = Node("Pair", children=[("items", None, None, Node("Leaf", scalars=[("value", "a")]))])
        self.assertRejects("stub_coordinate", frame(TAG_N, dumps(node_dict(0, pair))))

    def test_single_name_with_index_is_stub_coordinate(self):
        node = program_stub()
        node.names = [("label", 0, None, "main")]
        self.assertRejects("stub_coordinate", frame(TAG_N, dumps(node_dict(0, node))))

    def test_single_name_with_two_entries_is_stub_count(self):
        node = program_stub()
        node.names = [("label", None, None, "a"), ("label", None, None, "b")]
        self.assertRejects("stub_count", frame(TAG_N, dumps(node_dict(0, node))))

    def test_keyed_child_without_key_is_stub_coordinate(self):
        entry = Node("Leaf", scalars=[("value", "a")])
        stream = frame(TAG_N, dumps(node_dict(0, Node("Keyed", children=[("entries", None, None, entry)]))))
        self.assertRejects("stub_coordinate", stream)

    def test_keyed_repeated_key_is_duplicate_coordinate(self):
        keyed = Node(
            "Keyed",
            children=[("entries", None, "a", Node("Leaf", scalars=[("value", "x")])),
                      ("entries", None, "a", Node("Leaf", scalars=[("value", "y")]))],
            names=[("entries.key", None, "a", "a"), ("entries.key", None, "a", "a")],
        )
        self.assertRejects("duplicate_coordinate", frame(TAG_N, dumps(node_dict(0, keyed))))

    def test_keyed_key_and_value_counts_must_match(self):
        keyed = Node(
            "Keyed",
            children=[("entries", None, "a", Node("Leaf", scalars=[("value", "x")]))],
            names=[],
        )
        self.assertRejects("stub_count", frame(TAG_N, dumps(node_dict(0, keyed))))

    def test_keyed_key_and_value_coordinates_must_match(self):
        keyed = Node(
            "Keyed",
            children=[("entries", None, "a", Node("Leaf", scalars=[("value", "x")]))],
            names=[("entries.key", None, "b", "b")],
        )
        self.assertRejects("stub_coordinate", frame(TAG_N, dumps(node_dict(0, keyed))))

    def test_map_child_stub_field_must_not_have_sub(self):
        obj = node_dict(0, Node("Pair", children=[("items", 0, None, Node("Leaf", scalars=[("value", "a")]))]))
        obj["children"][0]["field"] = "items.key"
        self.assertRejects("stub_field", frame(TAG_N, dumps(obj)))

    def test_collection_absent_with_entries_is_stub_count(self):
        pair = Node("Pair", children=[("items", 0, None, Node("Leaf", scalars=[("value", "a")]))])
        obj = node_dict(0, pair)
        for entry in obj["presence"]:
            if entry["field"] == "items":
                entry["state"] = "Absent"
        self.assertRejects("stub_count", frame(TAG_N, dumps(obj)))

    def test_single_present_without_entry_is_state_mismatch_on_scalar(self):
        node = Node("Leaf", scalars=[])
        self.assertRejects("scalar_value", frame(TAG_N, dumps(node_dict(0, node))))

    # Presence list

    def test_presence_duplicate_entry(self):
        obj = node_dict(0, program_stub())
        obj["presence"].append(dict(obj["presence"][0]))
        self.assertRejects("duplicate_coordinate", frame(TAG_N, dumps(obj)))

    def test_presence_missing_entry(self):
        obj = node_dict(0, program_stub())
        obj["presence"] = [e for e in obj["presence"] if e["field"] != "body"]
        self.assertRejects("missing_field", frame(TAG_N, dumps(obj)))

    def test_presence_out_of_table_order(self):
        obj = node_dict(0, program_stub())
        obj["presence"][0], obj["presence"][1] = obj["presence"][1], obj["presence"][0]
        self.assertRejects("field_order", frame(TAG_N, dumps(obj)))

    def test_always_row_cannot_be_absent(self):
        obj = node_dict(0, program_stub())
        obj["presence"][0]["state"] = "Absent"
        self.assertRejects("presence_state", frame(TAG_N, dumps(obj)))

    def test_collection_row_cannot_be_present(self):
        obj = node_dict(0, program_stub())
        for entry in obj["presence"]:
            if entry["field"] == "body":
                entry["state"] = "Present"
        self.assertRejects("presence_state", frame(TAG_N, dumps(obj)))

    def test_infrastructure_row_is_never_framed(self):
        obj = node_dict(0, program_stub())
        obj["presence"].append({"field": "dirty", "state": "Present"})
        self.assertRejects("unknown_field", frame(TAG_N, dumps(obj)))

    def test_absent_optional_with_entry_is_stub_count(self):
        node = Node("Program", scalars=[("flag", True)], names=[("label", None, None, "main")])
        obj = node_dict(0, node)
        for entry in obj["presence"]:
            if entry["field"] == "label":
                entry["state"] = "Absent"
        self.assertRejects("stub_count", frame(TAG_N, dumps(obj)))

    # Scalars

    def test_scalar_entry_missing(self):
        obj = node_dict(0, program_stub())
        obj["scalars"] = [e for e in obj["scalars"] if e["field"] != "flag"]
        self.assertRejects("missing_field", frame(TAG_N, dumps(obj)))

    def test_scalar_duplicate_entry(self):
        obj = node_dict(0, program_stub())
        obj["scalars"].append(dict(obj["scalars"][0]))
        self.assertRejects("duplicate_coordinate", frame(TAG_N, dumps(obj)))

    def test_unknown_scalar_field(self):
        obj = node_dict(0, program_stub())
        obj["scalars"].append({"field": "bogus", "type": "bool", "value": True})
        self.assertRejects("unknown_field", frame(TAG_N, dumps(obj)))

    def test_scalar_type_differs_from_row_tag(self):
        obj = node_dict(0, program_stub())
        obj["scalars"][0]["type"] = "int32"
        self.assertRejects("scalar_type", frame(TAG_N, dumps(obj)))

    def test_scalar_value_wrong_shape(self):
        obj = node_dict(0, program_stub())
        obj["scalars"][0]["value"] = "yes"
        self.assertRejects("scalar_value", frame(TAG_N, dumps(obj)))

    def test_scalar_null_on_non_nilable_row(self):
        obj = node_dict(0, Node("Leaf", scalars=[("value", "x")]))
        obj["scalars"][0]["value"] = None
        self.assertRejects("scalar_value", frame(TAG_N, dumps(obj)))

    def test_nilable_scalar_null_is_allowed(self):
        stream = encode_frames(program_stub())
        self.assertEqual(verify(stream, stream_digest(stream)).nodes, 1)

    def test_text_scalar_not_canonical_base64(self):
        obj = node_dict(0, Node("Leaf", scalars=[("value", "x")]))
        obj["scalars"][0]["value"] = "not base64!"
        self.assertRejects("malformed_node", frame(TAG_N, dumps(obj)))

    def test_name_value_not_canonical_base64(self):
        obj = node_dict(0, program_stub())
        for entry in obj["presence"]:
            if entry["field"] == "label":
                entry["state"] = "Present"
        obj["names"] = [{"field": "label", "index": None, "map_key_base64": None, "value_base64": "not base64!"}]
        self.assertRejects("malformed_node", frame(TAG_N, dumps(obj)))

    # Top-level fields

    def test_excess_top_level_field(self):
        obj = node_dict(0, Node("Leaf", scalars=[("value", "x")]))
        obj["extra"] = 1
        self.assertRejects("excess_field", frame(TAG_N, dumps(obj)))

    def test_missing_top_level_field(self):
        obj = node_dict(0, Node("Leaf", scalars=[("value", "x")]))
        del obj["macro_lineage"]
        self.assertRejects("missing_field", frame(TAG_N, dumps(obj)))

    # Filename references

    def test_filename_substituted_under_same_reference(self):
        stream = encode_frames(build_positive(), filename_payloads={"main.iyi": snapshot("evil.iyi")})
        self.assertRejects("filename_unresolved", stream)

    def test_filename_reference_without_frame(self):
        stream = frame(TAG_N, dumps(node_dict(0, program_stub(filename="main.iyi"))))
        self.assertRejects("filename_unresolved", stream)

    def test_filename_frame_not_referenced_is_excess(self):
        stream = frame(TAG_F, snapshot("unused")) + frame(TAG_N, dumps(node_dict(0, program_stub())))
        self.assertRejects("filename_excess", stream)

    def test_filename_frame_without_node_is_orphan(self):
        self.assertRejects("filename_orphan", frame(TAG_F, snapshot("unused")))

    def test_filename_frame_before_alias_is_orphan(self):
        root = program_stub([("body", 0, None, Node("Program"))])
        stream = frame(TAG_N, dumps(node_dict(0, root))) + frame(TAG_F, snapshot("unused")) + alias(0)
        self.assertRejects("filename_orphan", stream)

    def test_filename_snapshot_with_nested_reference(self):
        payload = dumps({"filename_sha256": sha(b"x"), "kind": "file"})
        stream = frame(TAG_F, payload) + frame(TAG_N, dumps(node_dict(0, program_stub())))
        self.assertRejects("filename_nested_ref", stream)

    def test_filename_snapshot_not_object(self):
        stream = frame(TAG_F, b"[1]") + frame(TAG_N, dumps(node_dict(0, program_stub())))
        self.assertRejects("filename_malformed", stream)

    def test_inline_filename_snapshot_in_node_rejected(self):
        obj = node_dict(0, program_stub())
        obj["location"] = {"filename_snapshot": "{}", "line": 1}
        self.assertRejects("inline_filename", frame(TAG_N, dumps(obj)))

    def test_malformed_filename_reference(self):
        obj = node_dict(0, program_stub())
        obj["location"] = {"filename_sha256": "NOT-HEX", "line": 1}
        self.assertRejects("filename_malformed", frame(TAG_N, dumps(obj)))

    # Schema: shape of rows

    def test_schema_must_be_object(self):
        self.assertSchemaRejects("schema_malformed", [])

    def test_schema_missing_kinds(self):
        self.assertSchemaRejects("schema_missing_key", {"schema": vcf.SCHEMA_VERSION})

    def test_schema_wrong_version(self):
        doc = schema_doc()
        doc["schema"] = "iyi-field-schema/2"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_extra_top_level_key(self):
        doc = schema_doc()
        doc["notes"] = "x"
        self.assertSchemaRejects("schema_unknown_key", doc)

    def test_schema_empty_kinds(self):
        self.assertSchemaRejects("schema_malformed", {"schema": vcf.SCHEMA_VERSION, "kinds": {}})

    def test_schema_row_missing_key(self):
        doc = schema_doc()
        del doc["kinds"]["Leaf"][0]["base"]
        self.assertSchemaRejects("schema_missing_key", doc)

    def test_schema_row_extra_key(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["note"] = "x"
        self.assertSchemaRejects("schema_unknown_key", doc)

    def test_schema_unknown_klass(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["klass"] = "Mystery"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_role_disagrees_with_klass(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["role"] = "Name"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_bad_coordinate(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["coordinate"] = "Diagonal"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_bad_presence(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["presence"] = "Sometimes"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_bad_provenance(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["provenance"] = "Inferred"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_semantic_row_cannot_be_framed(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["provenance"] = "Semantic"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_framed_presence_null_is_unproven(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["presence"] = None
        self.assertSchemaRejects("unproven_field", doc)

    def test_schema_framed_nilable_null_is_unproven(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["nilable"] = None
        self.assertSchemaRejects("unproven_field", doc)

    def test_schema_always_must_not_be_nilable(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["nilable"] = True
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_optional_must_be_nilable(self):
        doc = schema_doc()
        doc["kinds"]["Program"][1]["nilable"] = False
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_indexed_list_must_be_collected(self):
        doc = schema_doc()
        doc["kinds"]["Pair"][0]["presence"] = "Always"
        doc["kinds"]["Pair"][0]["nilable"] = False
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_child_cannot_be_a_collection(self):
        doc = schema_doc()
        doc["kinds"]["Program"][4]["klass"] = "Child"
        doc["kinds"]["Program"][4]["role"] = "Child"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_scalar_must_be_single_coordinate(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["coordinate"] = "Indexed"
        doc["kinds"]["Leaf"][0]["presence"] = "Collection"
        doc["kinds"]["Leaf"][0]["nilable"] = False
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_framed_scalar_without_tag_is_unproven(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["scalar"] = None
        self.assertSchemaRejects("unproven_field", doc)

    def test_schema_nilable_tag_must_match_nilability(self):
        doc = schema_doc()
        doc["kinds"]["Program"][1]["scalar"] = "int32"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_unknown_scalar_tag(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["scalar"] = "float64"
        self.assertSchemaRejects("unknown_scalar_type", doc)

    def test_schema_non_scalar_row_cannot_carry_a_tag(self):
        doc = schema_doc()
        doc["kinds"]["Pair"][0]["scalar"] = "bool"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_unframed_row_cannot_carry_presence(self):
        doc = schema_doc()
        doc["kinds"]["Program"][5]["presence"] = "Always"
        self.assertSchemaRejects("schema_malformed", doc)

    def test_schema_unproven_type_expression(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["type_expression"] = "Float64"
        self.assertSchemaRejects("unproven_type_expression", doc)

    def test_schema_duplicate_field(self):
        doc = schema_doc()
        doc["kinds"]["Program"][1]["field"] = "flag"
        self.assertSchemaRejects("schema_duplicate_field", doc)

    def test_schema_null_type_expression_loads(self):
        doc = schema_doc()
        doc["kinds"]["Leaf"][0]["type_expression"] = None
        load_schema(doc)

    def test_schema_float_is_rejected_at_parse(self):
        with self.assertRaises(VerifyError) as ctx:
            vcf._parse_json(b'{"schema": 1.5}', "schema")
        self.assertEqual(ctx.exception.code, "float_number")

    # CLI

    def test_cli_accepts_good_pin_and_rejects_bad_pin(self):
        stream = encode_frames(build_positive())
        with tempfile.TemporaryDirectory() as tmp:
            schema_path = os.path.join(tmp, "schema.json")
            stream_path = os.path.join(tmp, "stream.bin")
            with open(schema_path, "w", encoding="utf-8") as handle:
                json.dump(schema_doc(), handle)
            with open(stream_path, "wb") as handle:
                handle.write(stream)
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                good = vcf.main([stream_path, "--schema", schema_path, "--sha256", stream_digest(stream)])
            self.assertEqual(good, 0)
            self.assertTrue(out.getvalue().startswith("OK sha256="))
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                bad = vcf.main([stream_path, "--schema", schema_path, "--sha256", "0" * 64])
            self.assertEqual(bad, 1)
            self.assertIn("digest_mismatch", err.getvalue())

    def test_remaining_scope_is_stated(self):
        self.assertGreaterEqual(len(vcf.REMAINING_BEYOND_PARSER), 6)


if __name__ == "__main__":
    unittest.main()
