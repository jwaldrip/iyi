#!/usr/bin/env python3
"""Behavioural and adversarial tests for the OperatorName and StructuralName derivations.

Covers contract C-OP and the structural contract S under the provenance ruling E1-E5 and U1-U6
(local://unnamed-param-provenance-ruling.md). Each non-anchor witness event is built from its own
emission records: Generated parts from recorded producers, NameSplice parts only for IDENT or CONST
witnesses, and never a claim writer. Mixed provenance across witnesses is valid. Source association
is not claimed here; the journal and pragma replay own it.

Every mutation is checked through the comparator's own entry points (derived_name, origin, name_value,
checked_origin) and must fail with its exact message.

Run: python3 bench/test_operator_derivation.py
"""

import copy
import hashlib
import os
import sys
import unittest

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
if BENCH_DIR not in sys.path:
    sys.path.insert(0, BENCH_DIR)

import frames_equivalent as frames  # noqa: E402

MODE = "Crystal"
MODULE = {"module": "sample/identity", "file": "sample.iyi"}

OP_ASSIGN_SPELLINGS = ["+=", "-=", "*=", "/=", "//=", "%=", "|=", "&=", "^=", "**=", "<<=", ">>=",
                       "||=", "&&=", "&+=", "&-=", "&*="]
COMMAND_SPELLINGS = ["`", "%x(", "%x[", "%x{", "%x<", "%x|"]

# (production, source, witnesses as (start, raw, token_kind, selection), rendered, producer_context)
CASES = [
    ("OpAssign", "x += 1", [(2, "+=", "+=", "Whole")], "+", "op_assign_operator"),
    ("OpAssign", "x **= 2", [(2, "**=", "**=", "Whole")], "**", "op_assign_operator"),
    ("OpAssign", "x &+= 2", [(2, "&+=", "&+=", "Whole")], "&+", "op_assign_operator"),
    ("OpAssign", "x ||= 2", [(2, "||=", "||=", "Whole")], "||", "op_assign_operator"),
    ("OpAssign", "x //= 2", [(2, "//=", "//=", "Whole")], "//", "op_assign_operator"),
    ("SignedNumber", "x = -1", [(4, "-1", "NUMBER", "SignedNumberSign")], "-", "method_name"),
    ("SignedNumber", "x = +7", [(4, "+7", "NUMBER", "SignedNumberSign")], "+", "method_name"),
    ("Index", "a[1]", [(1, "[", "[", "Whole"), (3, "]", "]", "Whole")], "[]", "method_name"),
    ("IndexQuery", "a[1]?", [(1, "[", "[", "Whole"), (3, "]", "]", "Whole"), (4, "?", "?", "Whole")],
     "[]?", "method_name"),
    ("IndexAssign", "a[1] = 2", [(1, "[", "[", "Whole"), (3, "]", "]", "Whole"), (5, "=", "=", "Whole")],
     "[]=", "method_name"),
    ("IndexAssign", "a[] = 2", [(1, "[]", "[]", "Whole"), (4, "=", "=", "Whole")], "[]=", "method_name"),
    ("Setter", "f.x = 1", [(2, "x", "IDENT", "Whole"), (4, "=", "=", "Whole")], "x=", "method_name"),
    ("Setter", "f.Foo = 1", [(2, "Foo", "CONST", "Whole"), (6, "=", "=", "Whole")], "Foo=", "method_name"),
    ("Command", "x = `ls`", [(4, "`", "DELIMITER_START", "Whole")], "`", "method_name"),
    ("Command", "x = %x(ls)", [(4, "%x(", "DELIMITER_START", "Whole")], "`", "method_name"),
]


def written(offset, anchor_kind="Call", role="method"):
    return {"kind": "Written", "source_identity": dict(MODULE), "input_byte_offset": offset,
            "anchor_kind": anchor_kind, "role": role}


def generated(start, end, producer="MacroVerbatim", emitter=None):
    return {"kind": "Generated", "start_offset": start, "end_offset": end,
            "emitter_origin": emitter, "producer": producer}


def astanchor(start, end, source_origin, emitter=None):
    return {"kind": "AstAnchor", "start_offset": start, "end_offset": end,
            "emitter_origin": emitter, "source_origin": source_origin}


def token_event(start, raw, kind, selection="Whole", mode=MODE, parts=None):
    end = start + len(raw.encode("utf-8"))
    if parts is None:
        covered_end = start + 1 if selection == "SignedNumberSign" else end
        parts = [generated(start, covered_end, "MacroTemplate")]
    return {"input_start": start, "input_end": end, "token_kind": kind, "token_text": raw,
            "lexical_mode": mode, "selection": selection, "byte_parts": parts}


def method_name_context(kind):
    return "method_name" if kind in ("IDENT", "CONST", "[]") else None


def operator(production, source, witnesses, rendered, context, anchor="written", mode=MODE):
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    nodes = [{"input_start": start, "input_end": start + len(raw.encode("utf-8")), "token_kind": kind,
              "raw_text": raw, "selection": selection, "event": None}
             for start, raw, kind, selection in witnesses]
    if anchor == "expanded":
        start, raw, kind, selection = witnesses[0]
        anchor_origin = {
            "kind": "Expanded",
            "invocation_origin": written(0),
            "macro_definition_origin": written(0, "Macro", "keyword"),
            "expansion_guard": "sha256:" + digest,
            "anchor_kind": "Call",
            "role": "method",
            "name_context": method_name_context(kind),
            "token_event": token_event(start, raw, kind, selection, mode),
            "anchor_use": {"kind": "Direct"},
        }
        for node in nodes[1:]:
            node["event"] = token_event(node["input_start"], node["raw_text"], node["token_kind"], "Whole", mode)
    else:
        anchor_origin = written(witnesses[0][0])
    return {
        "kind": "DerivedName",
        "derivation_kind": "OperatorName",
        "production": production,
        "anchor_origin": anchor_origin,
        "input_sha256": digest,
        "input_bytesize": len(source.encode("utf-8")),
        "lexical_mode": mode,
        "witnesses": nodes,
        "rendered_text": rendered,
        "producer_context": context,
    }


def op_assign(anchor="written"):
    return operator("OpAssign", "x += 1", [(2, "+=", "+=", "Whole")], "+", "op_assign_operator", anchor)


def signed_number(anchor="written"):
    return operator("SignedNumber", "x = -1", [(4, "-1", "NUMBER", "SignedNumberSign")], "-", "method_name", anchor)


def setter(anchor="written"):
    return operator("Setter", "f.x = 1", [(2, "x", "IDENT", "Whole"), (4, "=", "=", "Whole")], "x=",
                    "method_name", anchor)


def index_assign(anchor="written"):
    return operator("IndexAssign", "a[1] = 2",
                    [(1, "[", "[", "Whole"), (3, "]", "]", "Whole"), (5, "=", "=", "Whole")],
                    "[]=", "method_name", anchor)


def spliced_index():
    """Expanded a[1] whose anchor and later ] both carry one AstAnchor claim: claim writers are refused on witnesses."""
    claim = written(0)
    value = operator("Index", "a[1]", [(1, "[", "[", "Whole"), (3, "]", "]", "Whole")], "[]",
                     "method_name", "expanded")
    value["anchor_origin"]["token_event"]["byte_parts"] = [astanchor(1, 2, claim)]
    value["witnesses"][1]["event"]["byte_parts"] = [astanchor(2, 5, claim)]
    return value


def name_splice(start, end, raw, digest, size, kind="CONST"):
    """A NameSplice part whose Observed source token is a path segment of the same input."""
    token = {"lexical_origin": written(start, "Name", "path_segment"), "binding_origin": None,
             "context": "path_segment", "input_sha256": digest, "input_bytesize": size,
             "input_start": start, "input_end": end, "lexical_mode": MODE, "token_kind": kind,
             "raw_text": raw}
    return {"kind": "NameSplice", "start_offset": start, "end_offset": end, "emitter_origin": None,
            "source_name": {"kind": "Observed", "source_token": token}}


def structural_value(production, source, witnesses, fresh_index, anchor_origin, rendered, context, mode=MODE):
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    nodes = [{"input_start": start, "input_end": start + len(raw.encode("utf-8")), "token_kind": kind,
              "raw_text": raw, "selection": selection, "event": None}
             for start, raw, kind, selection in witnesses]
    return {"kind": "DerivedName", "derivation_kind": "StructuralName", "production": production,
            "anchor_origin": anchor_origin, "input_sha256": digest,
            "input_bytesize": len(source.encode("utf-8")), "lexical_mode": mode, "witnesses": nodes,
            "fresh_index": fresh_index, "rendered_text": rendered, "producer_context": context}


def unnamed_written(source="fun f(Int32)", witnesses=None):
    witnesses = witnesses or [(5, "(", "(", "Whole"), (6, "Int32", "CONST", "Whole")]
    return structural_value("UnnamedFunParameter", source, witnesses, None,
                            written(0, "FunDef", "keyword"), "", "parameter")


def unnamed_expanded(source="fun f(Int32)", witnesses=None):
    """Expanded FunDef keyword anchor; every witness carries its own Generated event by default."""
    value = unnamed_written(source, witnesses)
    digest = value["input_sha256"]
    value["anchor_origin"] = {"kind": "Expanded", "invocation_origin": written(0),
                              "macro_definition_origin": written(0, "Macro", "keyword"),
                              "expansion_guard": "sha256:" + digest, "anchor_kind": "FunDef",
                              "role": "keyword", "name_context": None,
                              "token_event": token_event(0, "fun", "IDENT"), "anchor_use": {"kind": "Direct"}}
    for witness in value["witnesses"]:
        witness["event"] = token_event(witness["input_start"], witness["raw_text"], witness["token_kind"], "Whole")
    return value


def short_written(fresh=0, source="x.map(&.foo)", witnesses=None):
    witnesses = witnesses or [(6, "&", "&", "Whole"), (7, ".", ".", "Whole")]
    rendered = "__arg" + str(fresh) if type(fresh) is int else ""
    return structural_value("ShortBlockArgument", source, witnesses, fresh,
                            written(6, "Block", "ampersand"), rendered, "local_reference")


def short_expanded(fresh=0):
    value = short_written(fresh)
    digest = value["input_sha256"]
    value["anchor_origin"] = {"kind": "Expanded", "invocation_origin": written(0),
                              "macro_definition_origin": written(0, "Macro", "keyword"),
                              "expansion_guard": "sha256:" + digest, "anchor_kind": "Block",
                              "role": "ampersand", "name_context": None,
                              "token_event": token_event(6, "&", "&"), "anchor_use": {"kind": "Direct"}}
    value["witnesses"][1]["event"] = token_event(7, ".", ".", "Whole")
    return value


class ProductionTests(unittest.TestCase):
    """Positive cases: every OperatorName production in both anchor classes, through every entry point."""

    def test_every_production_renders_in_both_anchor_classes(self):
        for anchor in ("written", "expanded"):
            for production, source, witnesses, rendered, context in CASES:
                with self.subTest(production=production, source=source, anchor=anchor):
                    value = operator(production, source, witnesses, rendered, context, anchor)
                    self.assertEqual(frames.derived_name(value, 0),
                                     (("Name", context), rendered.encode("utf-8")))

    def test_origin_and_name_value_consume_the_computed_text(self):
        for anchor in ("written", "expanded"):
            for production, source, witnesses, rendered, context in CASES:
                with self.subTest(production=production, source=source, anchor=anchor):
                    value = operator(production, source, witnesses, rendered, context, anchor)
                    self.assertEqual(frames.origin(value), ("Name", context))
                    self.assertEqual(frames.name_value({"kind": "Derived", "origin": value}, 0),
                                     rendered.encode("utf-8"))

    def test_every_op_assign_spelling_is_accepted(self):
        for spelling in OP_ASSIGN_SPELLINGS:
            with self.subTest(spelling=spelling):
                value = operator("OpAssign", "x " + spelling + " 1", [(2, spelling, spelling, "Whole")],
                                 spelling[:-1], "op_assign_operator")
                self.assertEqual(frames.derived_name(value, 0),
                                 (("Name", "op_assign_operator"), spelling[:-1].encode("utf-8")))

    def test_every_command_opener_is_accepted(self):
        for opener in COMMAND_SPELLINGS:
            with self.subTest(opener=opener):
                value = operator("Command", "x = " + opener, [(4, opener, "DELIMITER_START", "Whole")],
                                 "`", "method_name")
                self.assertEqual(frames.derived_name(value, 0)[1], b"`")

    def test_one_token_and_two_token_index_assignment_both_render(self):
        self.assertEqual(frames.derived_name(index_assign(), 0)[1], b"[]=")
        one_token = operator("IndexAssign", "a[] = 2", [(1, "[]", "[]", "Whole"), (4, "=", "=", "Whole")],
                             "[]=", "method_name", "expanded")
        self.assertEqual(frames.derived_name(one_token, 0)[1], b"[]=")

    def test_macro_emitter_on_a_later_witness_is_accepted(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["byte_parts"][0]["emitter_origin"] = written(5, "MacroDirective",
                                                                                    "expression")
        self.assertEqual(frames.derived_name(value, 0)[1], b"[]=")

    def test_checked_origin_accepts_an_expanded_operator(self):
        self.assertEqual(frames.checked_origin(op_assign("expanded")), ("Name", "op_assign_operator"))


class MixedProvenanceTests(unittest.TestCase):
    """E4: no two witnesses need the same source; mixed provenance across witnesses is valid."""

    def test_mixed_producers_across_later_witnesses_are_valid(self):
        value = operator("IndexQuery", "a[1]?",
                         [(1, "[", "[", "Whole"), (3, "]", "]", "Whole"), (4, "?", "?", "Whole")],
                         "[]?", "method_name", "expanded")
        value["witnesses"][1]["event"]["byte_parts"] = [generated(3, 4, "MacroTemplate")]
        value["witnesses"][2]["event"]["byte_parts"] = [generated(4, 5, "MacroVar")]
        self.assertEqual(frames.derived_name(value, 0)[1], b"[]?")


class RejectionTests(unittest.TestCase):
    """Adversarial OperatorName cases: each mutation is refused with its exact message."""

    def assertRejected(self, value, message, depth=0):
        with self.assertRaises(ValueError) as caught:
            frames.derived_name(value, depth)
        self.assertEqual(str(caught.exception), message)

    # Top-level shape and forged computed fields.

    def test_unknown_production_is_refused(self):
        value = op_assign()
        value["production"] = "Splat"
        self.assertRejected(value, "unknown operator production")

    def test_non_string_production_is_refused(self):
        value = op_assign()
        value["production"] = ["OpAssign"]
        self.assertRejected(value, "unknown operator production")

    def test_unknown_derivation_kind_is_refused(self):
        value = op_assign()
        value["derivation_kind"] = "OperatorNameX"
        self.assertRejected(value, "unknown derived name operation")

    def test_extra_field_is_refused(self):
        value = op_assign()
        value["extra"] = True
        self.assertRejected(value, "invalid provenance fields")

    def test_missing_computed_field_is_refused(self):
        value = op_assign()
        del value["producer_context"]
        self.assertRejected(value, "invalid provenance fields")

    def test_bad_input_guard_is_refused(self):
        value = op_assign()
        value["input_sha256"] = "A" * 64
        self.assertRejected(value, "invalid input guard")

    def test_unknown_lexical_mode_is_refused(self):
        value = op_assign()
        value["lexical_mode"] = "Ruby"
        self.assertRejected(value, "invalid token classification")

    def test_non_string_lexical_mode_is_refused(self):
        value = op_assign()
        value["lexical_mode"] = ["Crystal"]
        self.assertRejected(value, "invalid token classification")

    def test_oversized_input_bytesize_is_refused(self):
        value = op_assign()
        value["input_bytesize"] = 0x80000000
        self.assertRejected(value, "invalid provenance integer")

    def test_boolean_input_bytesize_is_refused(self):
        value = op_assign()
        value["input_bytesize"] = True
        self.assertRejected(value, "invalid provenance integer")

    def test_forged_rendered_text_is_refused(self):
        value = op_assign()
        value["rendered_text"] = "-"
        self.assertRejected(value, "derived operator rendering differs")

    def test_forged_rendered_text_is_refused_on_both_anchor_classes(self):
        for anchor in ("written", "expanded"):
            with self.subTest(anchor=anchor):
                value = signed_number(anchor)
                value["rendered_text"] = "+"
                self.assertRejected(value, "derived operator rendering differs")

    def test_forged_setter_rendering_is_refused(self):
        value = setter()
        value["rendered_text"] = "x"
        self.assertRejected(value, "derived operator rendering differs")

    def test_forged_producer_context_is_refused(self):
        value = op_assign()
        value["producer_context"] = "method_name"
        self.assertRejected(value, "derived operator context differs")

    def test_setter_with_op_assign_context_is_refused(self):
        value = setter()
        value["producer_context"] = "op_assign_operator"
        self.assertRejected(value, "derived operator context differs")

    def test_forged_name_is_refused_through_checked_origin_and_name_value(self):
        value = op_assign("expanded")
        value["rendered_text"] = "-"
        with self.assertRaises(ValueError) as caught:
            frames.checked_origin(value)
        self.assertEqual(str(caught.exception), "derived operator rendering differs")
        with self.assertRaises(ValueError) as caught:
            frames.name_value({"kind": "Derived", "origin": value}, 0)
        self.assertEqual(str(caught.exception), "derived operator rendering differs")

    def test_empty_witness_list_is_refused(self):
        value = op_assign()
        value["witnesses"] = []
        self.assertRejected(value, "invalid operator witness")

    def test_witness_count_above_the_table_bound_is_refused(self):
        value = op_assign()
        value["witnesses"] = [copy.deepcopy(value["witnesses"][0]) for _ in range(4)]
        self.assertRejected(value, "invalid operator witness")

    # OpAssign.

    def test_op_assign_witness_kind_forged_is_refused(self):
        value = op_assign()
        value["witnesses"][0]["token_kind"] = "+"
        self.assertRejected(value, "invalid operator witness")

    def test_op_assign_non_assignment_operator_is_refused(self):
        value = operator("OpAssign", "x + 1", [(2, "+", "+", "Whole")], "+", "op_assign_operator")
        self.assertRejected(value, "invalid operator witness")

    def test_op_assign_with_two_witnesses_is_refused(self):
        value = operator("OpAssign", "x += 1", [(2, "+=", "+=", "Whole"), (4, "=", "=", "Whole")],
                         "+", "op_assign_operator")
        self.assertRejected(value, "invalid operator witness")

    # SignedNumber.

    def test_signed_number_with_an_observed_operand_is_refused(self):
        value = operator("SignedNumber", "x = -x", [(4, "-x", "NUMBER", "SignedNumberSign")], "-",
                         "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_signed_number_with_a_bare_sign_is_refused(self):
        value = operator("SignedNumber", "x = -", [(4, "-", "NUMBER", "SignedNumberSign")], "-",
                         "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_signed_number_with_a_wrong_token_kind_is_refused(self):
        value = operator("SignedNumber", "x = -1", [(4, "-1", "IDENT", "SignedNumberSign")], "-",
                         "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_signed_number_with_a_whole_selection_is_refused(self):
        value = operator("SignedNumber", "x = -1", [(4, "-1", "NUMBER", "Whole")], "-", "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_signed_number_with_two_witnesses_is_refused(self):
        value = operator("SignedNumber", "x = -1+",
                         [(4, "-1", "NUMBER", "SignedNumberSign"), (6, "+", "+", "Whole")], "-",
                         "method_name")
        self.assertRejected(value, "invalid operator witness")

    # Index family.

    def test_index_brackets_out_of_order_are_refused(self):
        value = operator("Index", "a]1[", [(1, "]", "]", "Whole"), (3, "[", "[", "Whole")], "[]",
                         "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_index_with_a_query_suffix_is_refused(self):
        value = operator("Index", "a[1]?",
                         [(1, "[", "[", "Whole"), (3, "]", "]", "Whole"), (4, "?", "?", "Whole")], "[]",
                         "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_index_query_without_its_suffix_is_refused(self):
        value = operator("IndexQuery", "a[1]", [(1, "[", "[", "Whole"), (3, "]", "]", "Whole")], "[]?",
                         "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_index_query_suffix_with_a_wrong_kind_is_refused(self):
        value = operator("IndexQuery", "a[1]?",
                         [(1, "[", "[", "Whole"), (3, "]", "]", "Whole"), (4, "?", "IDENT", "Whole")],
                         "[]?", "method_name")
        self.assertRejected(value, "invalid operator witness")

    # `]?` is one suffix. A gap between `]` and `?` lexes as two tokens that are not the IndexQuery method.
    def test_index_query_with_a_space_before_the_suffix_is_refused(self):
        value = operator("IndexQuery", "a[1] ?",
                         [(1, "[", "[", "Whole"), (3, "]", "]", "Whole"), (5, "?", "?", "Whole")],
                         "[]?", "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_index_query_with_a_space_before_the_suffix_is_refused_when_expanded(self):
        value = operator("IndexQuery", "a[1] ?",
                         [(1, "[", "[", "Whole"), (3, "]", "]", "Whole"), (5, "?", "?", "Whole")],
                         "[]?", "method_name", "expanded")
        self.assertRejected(value, "invalid operator witness")

    def test_index_assign_mixing_both_forms_is_refused(self):
        value = operator("IndexAssign", "a[] = 2",
                         [(1, "[]", "[]", "Whole"), (3, "]", "]", "Whole"), (5, "=", "=", "Whole")],
                         "[]=", "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_index_assign_with_a_doubled_equals_terminator_is_refused(self):
        value = operator("IndexAssign", "a[1] == 2",
                         [(1, "[", "[", "Whole"), (3, "]", "]", "Whole"), (5, "==", "==", "Whole")],
                         "[]=", "method_name")
        self.assertRejected(value, "invalid operator witness")

    # Setter.

    def test_setter_name_with_a_predicate_suffix_is_refused(self):
        for name, source in (("x?", "f.x? = 1"), ("x!", "f.x! = 1")):
            with self.subTest(name=name):
                value = operator("Setter", source, [(2, name, "IDENT", "Whole"), (5, "=", "=", "Whole")],
                                 name + "=", "method_name")
                self.assertRejected(value, "invalid operator witness")

    def test_setter_with_an_instance_variable_name_is_refused(self):
        value = operator("Setter", "f.@x = 1", [(2, "@x", "INSTANCE_VAR", "Whole"), (5, "=", "=", "Whole")],
                         "@x=", "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_setter_without_its_equals_is_refused(self):
        value = operator("Setter", "f.x", [(2, "x", "IDENT", "Whole")], "x=", "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_setter_equals_with_a_wrong_kind_is_refused(self):
        value = operator("Setter", "f.x = 1", [(2, "x", "IDENT", "Whole"), (4, "=", "==", "Whole")],
                         "x=", "method_name")
        self.assertRejected(value, "invalid operator witness")

    # Command.

    def test_command_with_an_unknown_opener_is_refused(self):
        value = operator("Command", "x = %q(ls)", [(4, "%q(", "DELIMITER_START", "Whole")], "`",
                         "method_name")
        self.assertRejected(value, "invalid command opener")

    def test_command_with_a_wrong_token_kind_is_refused(self):
        value = operator("Command", "x = `ls`", [(4, "`", "IDENT", "Whole")], "`", "method_name")
        self.assertRejected(value, "invalid operator witness")

    def test_command_with_two_witnesses_is_refused(self):
        value = operator("Command", "x = ``",
                         [(4, "`", "DELIMITER_START", "Whole"), (5, "`", "DELIMITER_START", "Whole")], "`",
                         "method_name")
        self.assertRejected(value, "invalid operator witness")

    # Spans, order and selection.

    def test_span_end_mismatch_is_refused(self):
        value = op_assign()
        value["witnesses"][0]["input_end"] = 3
        self.assertRejected(value, "invalid operator witness span")

    def test_zero_width_span_is_refused(self):
        value = op_assign()
        value["witnesses"][0]["input_end"] = 2
        self.assertRejected(value, "invalid operator witness span")

    def test_span_past_the_input_is_refused(self):
        value = op_assign()
        value["witnesses"][0]["input_start"] = 5
        value["witnesses"][0]["input_end"] = 7
        self.assertRejected(value, "invalid operator witness span")

    def test_negative_span_is_refused(self):
        value = op_assign()
        value["witnesses"][0]["input_start"] = -1
        self.assertRejected(value, "invalid provenance integer")

    def test_raw_text_forged_without_moving_the_span_is_refused(self):
        value = op_assign()
        value["witnesses"][0]["raw_text"] = "+=x"
        self.assertRejected(value, "invalid operator witness span")

    def test_overlapping_witnesses_are_refused(self):
        value = operator("Index", "a[1]", [(1, "[", "[", "Whole"), (1, "]", "]", "Whole")], "[]",
                         "method_name")
        self.assertRejected(value, "invalid operator witness order")

    def test_reversed_witnesses_are_refused(self):
        value = operator("Index", "a[1]", [(3, "]", "]", "Whole"), (1, "[", "[", "Whole")], "[]",
                         "method_name")
        self.assertRejected(value, "invalid operator witness order")

    def test_selection_other_than_whole_on_a_non_signed_witness_is_refused(self):
        value = operator("Index", "a[1]", [(1, "[", "[", "SignedNumberSign"), (3, "]", "]", "Whole")],
                         "[]", "method_name")
        self.assertRejected(value, "invalid operator witness")

    # Anchor.

    def test_synthetic_anchor_is_refused(self):
        value = op_assign()
        value["anchor_origin"] = {"kind": "Synthetic", "parent_origin": written(2),
                                  "synthesis_kind": "compound_assignment", "structural_slot": "getter"}
        self.assertRejected(value, "invalid operator anchor")

    def test_derived_anchor_is_refused(self):
        value = op_assign()
        value["anchor_origin"] = {"kind": "DerivedName"}
        self.assertRejected(value, "invalid operator anchor")

    def test_anchor_with_the_wrong_role_is_refused(self):
        value = op_assign()
        value["anchor_origin"] = written(2, "Name", "method_name")
        self.assertRejected(value, "invalid operator anchor")

    def test_written_anchor_offset_mismatch_is_refused(self):
        value = op_assign()
        value["anchor_origin"] = written(0)
        self.assertRejected(value, "operator anchor offset mismatch")

    def test_written_anchor_with_a_witness_event_is_refused(self):
        value = index_assign()
        value["witnesses"][1]["event"] = token_event(3, "]", "]")
        self.assertRejected(value, "invalid operator witness provenance")

    def test_expanded_guard_from_another_input_is_refused(self):
        value = op_assign("expanded")
        value["anchor_origin"]["expansion_guard"] = "sha256:" + "0" * 64
        self.assertRejected(value, "operator witnesses use different inputs")

    def test_expanded_anchor_in_another_lexical_mode_is_refused(self):
        value = op_assign("expanded")
        value["anchor_origin"]["token_event"]["lexical_mode"] = "Iyi"
        self.assertRejected(value, "operator witnesses use different inputs")

    def test_expanded_anchor_at_another_position_is_refused(self):
        value = op_assign("expanded")
        value["anchor_origin"]["token_event"] = token_event(0, "+=", "+=")
        self.assertRejected(value, "operator anchor token differs from witness 0")

    def test_expanded_anchor_with_another_selection_is_refused(self):
        value = signed_number("expanded")
        value["anchor_origin"]["token_event"] = token_event(4, "-1", "NUMBER", "Whole")
        self.assertRejected(value, "operator anchor token differs from witness 0")

    def test_expanded_anchor_with_a_name_role_is_refused(self):
        value = setter("expanded")
        value["anchor_origin"]["anchor_kind"] = "Name"
        value["anchor_origin"]["role"] = "method_name"
        self.assertRejected(value, "invalid operator anchor")

    def test_expanded_witness_zero_carrying_an_event_is_refused(self):
        value = op_assign("expanded")
        value["witnesses"][0]["event"] = token_event(2, "+=", "+=")
        self.assertRejected(value, "invalid operator witness provenance")

    # Later expanded witnesses: event identity and recorded parts.

    def test_later_witness_without_an_event_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][1]["event"] = None
        self.assertRejected(value, "invalid operator witness provenance")

    def test_later_witness_event_in_another_mode_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["lexical_mode"] = "Iyi"
        self.assertRejected(value, "operator witnesses use different inputs")

    def test_later_witness_event_with_other_token_text_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["token_text"] = "=="
        self.assertRejected(value, "invalid operator witness provenance")

    def test_later_witness_event_with_other_span_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][1]["event"]["input_end"] = 5
        self.assertRejected(value, "invalid operator witness provenance")

    def test_later_witness_event_with_a_signed_selection_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["selection"] = "SignedNumberSign"
        self.assertRejected(value, "invalid operator witness provenance")

    def test_later_witness_with_a_non_recorded_producer_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["byte_parts"][0]["producer"] = "UnrecordedProducer"
        self.assertRejected(value, "invalid operator witness provenance")

    def test_later_witness_part_not_attributed_by_macro_emission_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["byte_parts"] = [generated(6, 7)]
        self.assertRejected(value, "witness bytes not attributed by macro emission")

    def test_later_witness_part_extending_past_the_span_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["byte_parts"] = [generated(5, 7)]
        self.assertRejected(value, "invalid operator witness provenance")

    def test_later_witness_zero_width_part_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["byte_parts"] = [generated(5, 5)]
        self.assertRejected(value, "invalid operator witness provenance")

    def test_later_witness_without_parts_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["byte_parts"] = []
        self.assertRejected(value, "invalid operator witness provenance")

    def test_later_witness_emitter_outside_a_macro_directive_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["byte_parts"][0]["emitter_origin"] = written(5, "Call", "method")
        self.assertRejected(value, "invalid operator witness provenance")

    def test_anchor_part_that_splits_a_utf8_character_is_refused(self):
        # "xé" is three bytes; the first part ends inside the two-byte é.
        value = operator("Setter", "f.xé = 1", [(2, "xé", "IDENT", "Whole"), (6, "=", "=", "Whole")],
                         "xé=", "method_name", "expanded")
        value["anchor_origin"]["token_event"]["byte_parts"] = [generated(2, 4, "MacroTemplate"),
                                                               generated(4, 5, "MacroTemplate")]
        self.assertRejected(value, "emission splits UTF-8")

    # Graph bounds.

    def test_nesting_beyond_the_origin_bound_is_refused(self):
        self.assertRejected(op_assign(), "invalid origin depth", depth=128)
        with self.assertRaises(ValueError) as caught:
            frames.origin(op_assign(), depth=129)
        self.assertEqual(str(caught.exception), "invalid origin depth")

    def test_oversized_unfolded_graph_is_refused_before_validation(self):
        value = op_assign("expanded")
        value["padding"] = "a" * (9 * 1024 * 1024)
        with self.assertRaises(ValueError) as caught:
            frames.checked_origin(value)
        self.assertEqual(str(caught.exception), "origin size limit exceeded")


class ClaimWriterTests(unittest.TestCase):
    """E2: claim writers are never used for non-anchor witnesses (the A1 same-source clause is withdrawn)."""

    def assertRejected(self, value, message):
        with self.assertRaises(ValueError) as caught:
            frames.derived_name(value, 0)
        self.assertEqual(str(caught.exception), message)

    def test_claim_writer_on_a_later_witness_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["byte_parts"] = [astanchor(5, 6, written(0, "Call", "method"))]
        self.assertRejected(value, "invalid operator witness provenance")

    def test_claim_writer_sharing_the_anchor_claim_is_still_refused(self):
        self.assertRejected(spliced_index(), "invalid operator witness provenance")

    def test_claim_writer_mixed_with_generated_is_refused(self):
        value = operator("Index", "a[1]", [(1, "[", "[", "Whole"), (3, "]", "]", "Whole")], "[]",
                         "method_name", "expanded")
        value["witnesses"][1]["event"]["byte_parts"] = [generated(3, 4, "MacroTemplate"),
                                                        astanchor(3, 4, written(0))]
        self.assertRejected(value, "invalid operator witness provenance")


class StructuralNameTests(unittest.TestCase):
    """Contract S under U1 to U6 and E1 to E5: recomputed name and type, witnesses, anchor, forged events."""

    def assertRejected(self, value, message, depth=0):
        with self.assertRaises(ValueError) as caught:
            frames.derived_name(value, depth)
        self.assertEqual(str(caught.exception), message)

    # Written and accepted forms.

    def test_unnamed_parameter_renders_an_empty_name(self):
        self.assertEqual(frames.derived_name(unnamed_written(), 0), (("Name", "parameter"), b""))

    def test_unnamed_comma_separator_is_accepted(self):
        value = unnamed_written("fun f,Int32", [(5, ",", ",", "Whole"), (6, "Int32", "CONST", "Whole")])
        self.assertEqual(frames.derived_name(value, 0), (("Name", "parameter"), b""))

    def test_short_block_written_renders_its_fresh_name(self):
        self.assertEqual(frames.derived_name(short_written(0), 0), (("Name", "local_reference"), b"__arg0"))

    def test_fresh_index_renders_its_decimal_value(self):
        self.assertEqual(frames.derived_name(short_written(12), 0)[1], b"__arg12")

    def test_short_block_expanded_generated_is_accepted(self):
        self.assertEqual(frames.derived_name(short_expanded(), 0)[1], b"__arg0")

    def test_structural_reaches_origin_name_value_and_checked_origin(self):
        self.assertEqual(frames.origin(short_written()), ("Name", "local_reference"))
        self.assertEqual(frames.name_value({"kind": "Derived", "origin": short_written()}, 0), b"__arg0")
        self.assertEqual(frames.name_value({"kind": "Derived", "origin": unnamed_written()}, 0), b"")
        self.assertEqual(frames.checked_origin(short_expanded()), ("Name", "local_reference"))

    # Expanded UnnamedFunParameter (U1 to U6, E2 and E5 shape).

    def test_expanded_unnamed_with_generated_events_is_accepted(self):
        self.assertEqual(frames.derived_name(unnamed_expanded(), 0), (("Name", "parameter"), b""))

    def test_expanded_unnamed_with_mixed_provenance_across_witnesses_is_accepted(self):
        # PC-3 shape: separator from template text, head Int32 from a NameSplice of the spliced path.
        value = unnamed_expanded()
        digest, size = value["input_sha256"], value["input_bytesize"]
        value["witnesses"][1]["event"]["byte_parts"] = [name_splice(6, 11, "Int32", digest, size)]
        self.assertEqual(frames.derived_name(value, 0), (("Name", "parameter"), b""))

    def test_expanded_unnamed_with_adjacent_different_producers_is_accepted(self):
        value = unnamed_expanded()
        value["witnesses"][1]["event"]["byte_parts"] = [generated(6, 8, "MacroTemplate"),
                                                        generated(8, 11, "MacroVar")]
        self.assertEqual(frames.derived_name(value, 0), (("Name", "parameter"), b""))

    def test_expanded_unnamed_name_splice_on_the_separator_is_refused(self):
        value = unnamed_expanded()
        digest, size = value["input_sha256"], value["input_bytesize"]
        value["witnesses"][0]["event"]["byte_parts"] = [name_splice(5, 6, "(", digest, size)]
        self.assertRejected(value, "invalid structural witness provenance")

    def test_expanded_unnamed_name_splice_with_forged_bytes_is_refused(self):
        value = unnamed_expanded()
        digest, size = value["input_sha256"], value["input_bytesize"]
        value["witnesses"][1]["event"]["byte_parts"] = [name_splice(6, 11, "Int33", digest, size)]
        self.assertRejected(value, "invalid structural witness provenance")

    def test_expanded_unnamed_partial_name_splice_leaves_bytes_unattributed(self):
        value = unnamed_expanded()
        digest, size = value["input_sha256"], value["input_bytesize"]
        value["witnesses"][1]["event"]["byte_parts"] = [name_splice(6, 10, "Int3", digest, size)]
        self.assertRejected(value, "witness bytes not attributed by macro emission")

    def test_expanded_unnamed_gap_before_a_part_is_unattributed(self):
        value = unnamed_expanded()
        value["witnesses"][1]["event"]["byte_parts"] = [generated(7, 11, "MacroTemplate")]
        self.assertRejected(value, "witness bytes not attributed by macro emission")

    def test_expanded_unnamed_claim_writer_on_a_witness_is_refused(self):
        value = unnamed_expanded()
        value["witnesses"][1]["event"]["byte_parts"] = [astanchor(6, 11, written(0, "FunDef", "keyword"))]
        self.assertRejected(value, "invalid structural witness provenance")

    def test_expanded_unnamed_unmerged_adjacent_generated_parts_are_refused(self):
        value = unnamed_expanded()
        value["witnesses"][1]["event"]["byte_parts"] = [generated(6, 8, "MacroTemplate"),
                                                        generated(8, 11, "MacroTemplate")]
        self.assertRejected(value, "invalid structural witness provenance")

    def test_expanded_unnamed_anchor_that_is_not_fun_is_refused(self):
        value = unnamed_expanded()
        value["anchor_origin"]["token_event"] = token_event(0, "fn", "IDENT")
        self.assertRejected(value, "invalid structural anchor")

    def test_expanded_unnamed_anchor_in_another_mode_is_refused(self):
        value = unnamed_expanded()
        value["anchor_origin"]["token_event"]["lexical_mode"] = "Iyi"
        self.assertRejected(value, "invalid structural anchor")

    def test_expanded_unnamed_anchor_after_its_witnesses_is_refused(self):
        value = unnamed_expanded()
        value["anchor_origin"]["token_event"] = token_event(6, "fun", "IDENT")
        self.assertRejected(value, "anchor does not precede witnesses")

    def test_expanded_unnamed_guard_from_another_input_is_refused(self):
        value = unnamed_expanded()
        value["anchor_origin"]["expansion_guard"] = "sha256:" + "0" * 64
        self.assertRejected(value, "structural witnesses use different inputs")

    def test_expanded_unnamed_head_that_is_an_ellipsis_is_refused(self):
        value = unnamed_expanded("fun f(...)", [(5, "(", "(", "Whole"), (6, "...", "...", "Whole")])
        self.assertRejected(value, "unnamed parameter head is not the first type token")

    def test_expanded_unnamed_head_that_is_an_identifier_is_refused(self):
        value = unnamed_expanded("fun n(x)", [(5, "(", "(", "Whole"), (6, "x", "IDENT", "Whole")])
        self.assertRejected(value, "unnamed parameter head is not the first type token")

    def test_expanded_unnamed_missing_separator_event_is_refused(self):
        value = unnamed_expanded()
        value["witnesses"][0]["event"] = None
        self.assertRejected(value, "invalid structural witness provenance")

    def test_expanded_unnamed_with_a_written_separator_event_is_still_bound_by_u_rules(self):
        # A Written-style null event on the head makes the Expanded chain incomplete.
        value = unnamed_expanded()
        value["witnesses"][1]["event"] = None
        self.assertRejected(value, "invalid structural witness provenance")

    def test_written_unnamed_head_that_is_an_ellipsis_is_refused(self):
        value = unnamed_written("fun f(...)", [(5, "(", "(", "Whole"), (6, "...", "...", "Whole")])
        self.assertRejected(value, "unnamed parameter head is not the first type token")

    def test_written_unnamed_head_that_is_an_identifier_is_refused(self):
        value = unnamed_written("fun n(x)", [(5, "(", "(", "Whole"), (6, "x", "IDENT", "Whole")])
        self.assertRejected(value, "unnamed parameter head is not the first type token")

    # Written unnamed anchors (U2 and journal-only U1).

    def test_written_unnamed_anchor_must_precede_its_separator(self):
        value = unnamed_written()
        value["anchor_origin"] = written(5, "FunDef", "keyword")
        self.assertRejected(value, "anchor does not precede witnesses")

    def test_anchor_role_must_match_the_production(self):
        value = unnamed_written()
        value["anchor_origin"] = written(0, "Block", "ampersand")
        self.assertRejected(value, "invalid structural anchor")
        value = short_written()
        value["anchor_origin"] = written(6, "FunDef", "keyword")
        self.assertRejected(value, "invalid structural anchor")

    def test_synthetic_anchor_is_refused(self):
        value = short_written()
        value["anchor_origin"] = {"kind": "Synthetic", "parent_origin": written(6, "Block", "ampersand"),
                                  "synthesis_kind": "block_to_proc", "structural_slot": "proc"}
        self.assertRejected(value, "invalid structural anchor")

    def test_written_source_refuses_token_events(self):
        value = unnamed_written()
        value["witnesses"][0]["event"] = token_event(5, "(", "(")
        self.assertRejected(value, "structural witness has a token event for written source")

    def test_written_short_block_anchor_must_equal_the_ampersand_offset(self):
        value = short_written()
        value["anchor_origin"] = written(7, "Block", "ampersand")
        self.assertRejected(value, "structural anchor offset mismatch")

    # Production, input and witness shape.

    def test_unknown_production_is_refused(self):
        value = short_written()
        value["production"] = "Splat"
        self.assertRejected(value, "invalid structural production")

    def test_non_string_production_is_refused(self):
        value = short_written()
        value["production"] = ["ShortBlockArgument"]
        self.assertRejected(value, "invalid structural production")

    def test_empty_input_is_refused(self):
        value = short_written()
        value["input_bytesize"] = 0
        self.assertRejected(value, "invalid structural input")

    def test_unknown_lexical_mode_is_refused(self):
        value = short_written()
        value["lexical_mode"] = "Ruby"
        self.assertRejected(value, "invalid structural input")

    def test_bad_input_guard_is_refused(self):
        value = short_written()
        value["input_sha256"] = "A" * 64
        self.assertRejected(value, "invalid input guard")

    def test_witness_count_is_fixed_at_two(self):
        for witnesses in ([(5, "(", "(", "Whole")],
                          [(5, "(", "(", "Whole"), (6, "Int32", "CONST", "Whole"), (11, ")", ")", "Whole")]):
            with self.subTest(count=len(witnesses)):
                self.assertRejected(unnamed_written(witnesses=witnesses), "structural witness differs")

    def test_unnamed_separator_must_be_paren_or_comma(self):
        value = unnamed_written(witnesses=[(5, "-", "-", "Whole"), (6, "Int32", "CONST", "Whole")])
        self.assertRejected(value, "structural witness differs")

    def test_unnamed_separator_kind_must_equal_its_spelling(self):
        value = unnamed_written(witnesses=[(5, "(", "IDENT", "Whole"), (6, "Int32", "CONST", "Whole")])
        self.assertRejected(value, "structural witness differs")

    def test_unnamed_type_head_must_be_a_whole_token(self):
        value = unnamed_written(witnesses=[(5, "(", "(", "Whole"), (6, "Int32", "CONST", "SignedNumberSign")])
        self.assertRejected(value, "structural witness differs")

    def test_unnamed_parameter_cannot_carry_a_fresh_index(self):
        value = unnamed_written()
        value["fresh_index"] = 0
        self.assertRejected(value, "structural witness differs")

    def test_short_block_requires_a_fresh_index(self):
        self.assertRejected(short_written(None), "invalid short block fresh index")

    def test_short_block_fresh_index_must_be_a_non_negative_integer(self):
        for fresh in (-1, True, "0", 2 ** 31):
            with self.subTest(fresh=fresh):
                self.assertRejected(short_written(fresh), "invalid short block fresh index")

    def test_short_block_requires_the_ampersand_dot_sequence(self):
        value = short_written(witnesses=[(6, "&", "&", "Whole"), (7, ",", ",", "Whole")])
        self.assertRejected(value, "structural witness differs")

    def test_short_block_witnesses_must_be_whole(self):
        value = short_written(witnesses=[(6, "&", "&", "SignedNumberSign"), (7, ".", ".", "Whole")])
        self.assertRejected(value, "structural witness differs")

    def test_forged_short_block_name_is_refused(self):
        value = short_written(0)
        value["rendered_text"] = "__arg1"
        self.assertRejected(value, "derived structural rendering differs")

    def test_forged_unnamed_rendering_and_context_are_refused(self):
        value = unnamed_written()
        value["rendered_text"] = "x"
        self.assertRejected(value, "derived structural rendering differs")
        value = unnamed_written()
        value["producer_context"] = "local_reference"
        self.assertRejected(value, "derived structural rendering differs")

    def test_forged_short_block_context_is_refused(self):
        value = short_written(0)
        value["producer_context"] = "parameter"
        self.assertRejected(value, "derived structural rendering differs")

    def test_span_end_mismatch_is_refused(self):
        value = short_written()
        value["witnesses"][1]["input_end"] = 9
        self.assertRejected(value, "invalid structural witness span")

    def test_negative_offset_is_refused(self):
        value = short_written()
        value["witnesses"][0]["input_start"] = -1
        self.assertRejected(value, "invalid provenance integer")

    def test_span_past_the_input_is_refused(self):
        value = short_written()
        value["witnesses"][1]["input_start"] = 12
        value["witnesses"][1]["input_end"] = 13
        self.assertRejected(value, "invalid structural witness span")

    def test_overlapping_witnesses_are_refused(self):
        value = short_written(witnesses=[(6, "&", "&", "Whole"), (6, ".", ".", "Whole")])
        self.assertRejected(value, "structural witnesses overlap or are out of order")

    # Expanded ShortBlockArgument chain (E1 for witness 0, E2 and E3 for the rest).

    def test_expanded_anchor_event_must_equal_the_first_witness(self):
        value = short_expanded()
        value["anchor_origin"]["token_event"] = token_event(0, "&", "&")
        self.assertRejected(value, "structural anchor event differs from first witness")

    def test_expanded_guard_from_another_input_is_refused(self):
        value = short_expanded()
        value["anchor_origin"]["expansion_guard"] = "sha256:" + "0" * 64
        self.assertRejected(value, "structural witnesses use different inputs")

    def test_expanded_first_witness_must_not_carry_an_event(self):
        value = short_expanded()
        value["witnesses"][0]["event"] = token_event(6, "&", "&")
        self.assertRejected(value, "invalid structural witness provenance")

    def test_expanded_later_witness_needs_an_event(self):
        value = short_expanded()
        value["witnesses"][1]["event"] = None
        self.assertRejected(value, "invalid structural witness provenance")

    def test_expanded_later_witness_in_another_mode_is_refused(self):
        value = short_expanded()
        value["witnesses"][1]["event"]["lexical_mode"] = "Iyi"
        self.assertRejected(value, "structural witnesses use different inputs")

    def test_expanded_later_event_must_match_its_own_fields(self):
        value = short_expanded()
        value["witnesses"][1]["event"]["token_text"] = "x"
        self.assertRejected(value, "invalid structural witness provenance")

    def test_expanded_claim_writer_on_a_later_witness_is_refused(self):
        value = short_expanded()
        value["witnesses"][1]["event"]["byte_parts"] = [astanchor(6, 8, written(0, "Block", "ampersand"))]
        self.assertRejected(value, "invalid structural witness provenance")

    def test_expanded_mixed_generated_and_claim_writer_is_refused(self):
        value = short_expanded()
        value["witnesses"][1]["event"]["byte_parts"] = [generated(7, 8, "MacroTemplate"),
                                                        astanchor(7, 8, written(0, "Block", "ampersand"))]
        self.assertRejected(value, "invalid structural witness provenance")


class StructuralBudgetTests(unittest.TestCase):
    """Offsets and graph budgets for StructuralName, enforced by the shared origin bounds."""

    def test_depth_bound_is_enforced(self):
        with self.assertRaises(ValueError) as caught:
            frames.origin(short_written(), depth=129)
        self.assertEqual(str(caught.exception), "invalid origin depth")

    def test_oversized_structural_graph_is_refused_before_validation(self):
        value = short_expanded()
        value["padding"] = "a" * (9 * 1024 * 1024)
        with self.assertRaises(ValueError) as caught:
            frames.checked_origin(value)
        self.assertEqual(str(caught.exception), "origin size limit exceeded")


class FreshIndexOrderTests(unittest.TestCase):
    """Across one capture, fresh indices strictly increase with witness offset; gaps are allowed."""

    def assertRefused(self, entries, message):
        with self.assertRaises(ValueError) as caught:
            frames.fresh_index_order(entries)
        self.assertEqual(str(caught.exception), message)

    def test_increasing_indices_with_gaps_are_accepted(self):
        self.assertIsNone(frames.fresh_index_order([(6, 0), (20, 3), (30, 4)]))

    def test_entries_are_ordered_by_offset_before_checking(self):
        self.assertIsNone(frames.fresh_index_order([(20, 1), (6, 0)]))

    def test_decreasing_indices_are_refused(self):
        self.assertRefused([(6, 3), (20, 1)], "fresh index order differs")

    def test_repeated_index_is_refused(self):
        self.assertRefused([(6, 2), (20, 2)], "fresh index order differs")

    def test_colliding_offsets_are_refused(self):
        self.assertRefused([(6, 0), (6, 1)], "fresh index offsets collide")

    def test_non_integer_entries_are_refused(self):
        self.assertRefused([(6, "0")], "invalid provenance integer")



BARE_KEYWORDS = {"BareSplatParameter": ("def", "Def"), "MacroBareSplatParameter": ("macro", "Macro")}


def bare_written(source="def f(*, y)", production="BareSplatParameter"):
    """Written declaration: the keyword precedes the star, and neither witness carries an event."""
    _, kind = BARE_KEYWORDS[production]
    star = source.index("*")
    witnesses = [(star, "*", "*", "Whole"), (star + 1, ",", ",", "Whole")]
    return structural_value(production, source, witnesses, None, written(0, kind, "keyword"), "", "parameter")


def bare_expanded(source="def f(*, y)", production="BareSplatParameter"):
    """Expanded declaration: the keyword is the anchor, and each witness carries its own Generated event."""
    keyword, kind = BARE_KEYWORDS[production]
    value = bare_written(source, production)
    value["anchor_origin"] = {"kind": "Expanded", "invocation_origin": written(0),
                              "macro_definition_origin": written(0, "Macro", "keyword"),
                              "expansion_guard": "sha256:" + value["input_sha256"], "anchor_kind": kind,
                              "role": "keyword", "name_context": None,
                              "token_event": token_event(0, keyword, "IDENT"), "anchor_use": {"kind": "Direct"}}
    for witness in value["witnesses"]:
        witness["event"] = token_event(witness["input_start"], witness["raw_text"], witness["token_kind"], "Whole")
    return value


class BareSplatStructuralTests(unittest.TestCase):
    """Plan C: BareSplatParameter and MacroBareSplatParameter.

    The shape is the fixed `*`, `,` pair anchored on its declaration keyword, with each witness's E2 event
    attributed independently. Strict occurrence binding is a separate authority and is not claimed here.
    """

    def assertRejected(self, value, message, depth=0):
        with self.assertRaises(ValueError) as caught:
            frames.derived_name(value, depth)
        self.assertEqual(str(caught.exception), message)

    def test_written_def_bare_splat_is_accepted(self):
        self.assertEqual(frames.derived_name(bare_written("def f(*, y)"), 0), (("Name", "parameter"), b""))

    def test_written_def_bare_splat_after_a_positional_is_accepted(self):
        self.assertEqual(frames.derived_name(bare_written("def f(x, *, y)"), 0), (("Name", "parameter"), b""))

    def test_written_macro_bare_splat_is_accepted(self):
        value = bare_written("macro f(*, y)", "MacroBareSplatParameter")
        self.assertEqual(frames.derived_name(value, 0), (("Name", "parameter"), b""))

    def test_expanded_def_bare_splat_with_own_events_is_accepted(self):
        self.assertEqual(frames.derived_name(bare_expanded(), 0), (("Name", "parameter"), b""))

    def test_expanded_macro_bare_splat_is_accepted(self):
        value = bare_expanded("macro f(*, y)", "MacroBareSplatParameter")
        self.assertEqual(frames.derived_name(value, 0), (("Name", "parameter"), b""))

    def test_expanded_bare_splat_with_mixed_producers_across_both_witnesses_is_accepted(self):
        value = bare_expanded()
        value["witnesses"][0]["event"]["byte_parts"] = [generated(6, 7, "MacroTemplate")]
        value["witnesses"][1]["event"]["byte_parts"] = [generated(7, 8, "MacroVar")]
        self.assertEqual(frames.derived_name(value, 0), (("Name", "parameter"), b""))

    def test_bare_splat_reaches_origin_name_value_and_checked_origin(self):
        self.assertEqual(frames.origin(bare_written()), ("Name", "parameter"))
        self.assertEqual(frames.name_value({"kind": "Derived", "origin": bare_written()}, 0), b"")
        self.assertEqual(frames.checked_origin(bare_expanded()), ("Name", "parameter"))

    def test_fresh_index_on_a_bare_splat_is_refused(self):
        value = bare_written()
        value["fresh_index"] = 3
        self.assertRejected(value, "structural witness differs")

    def test_bare_star_without_a_following_comma_is_refused(self):
        value = bare_written("def f(*)")
        value["witnesses"] = value["witnesses"][:1]
        self.assertRejected(value, "structural witness differs")

    def test_named_splat_relabelled_as_bare_is_refused(self):
        value = structural_value("BareSplatParameter", "def f(*xs)",
                                 [(6, "*", "*", "Whole"), (7, "xs", "IDENT", "Whole")], None,
                                 written(0, "Def", "keyword"), "", "parameter")
        self.assertRejected(value, "structural witness differs")

    def test_star_whose_token_kind_is_an_identifier_is_refused(self):
        value = bare_written()
        value["witnesses"][0]["token_kind"] = "IDENT"
        self.assertRejected(value, "structural witness differs")

    def test_comma_whose_token_kind_is_an_identifier_is_refused(self):
        value = bare_written()
        value["witnesses"][1]["token_kind"] = "IDENT"
        self.assertRejected(value, "structural witness differs")

    def test_partial_selection_on_the_star_is_refused(self):
        value = bare_written()
        value["witnesses"][0]["selection"] = "SignedNumberSign"
        self.assertRejected(value, "structural witness differs")

    def test_bare_splat_anchored_on_fun_is_refused(self):
        value = bare_written()
        value["anchor_origin"] = written(0, "FunDef", "keyword")
        self.assertRejected(value, "invalid structural anchor")

    def test_macro_bare_splat_anchored_on_def_is_refused(self):
        value = bare_written("macro f(*, y)", "MacroBareSplatParameter")
        value["anchor_origin"] = written(0, "Def", "keyword")
        self.assertRejected(value, "invalid structural anchor")

    def test_def_bare_splat_anchored_on_macro_is_refused(self):
        value = bare_written()
        value["anchor_origin"] = written(0, "Macro", "keyword")
        self.assertRejected(value, "invalid structural anchor")

    def test_written_anchor_must_precede_the_star(self):
        value = bare_written()
        value["anchor_origin"] = written(6, "Def", "keyword")
        self.assertRejected(value, "anchor does not precede witnesses")

    def test_written_bare_splat_refuses_token_events(self):
        value = bare_written()
        value["witnesses"][0]["event"] = token_event(6, "*", "*")
        self.assertRejected(value, "structural witness has a token event for written source")

    def test_expanded_bare_splat_keyword_must_be_def(self):
        value = bare_expanded()
        value["anchor_origin"]["token_event"] = token_event(0, "fun", "IDENT")
        self.assertRejected(value, "invalid structural anchor")

    def test_expanded_macro_bare_splat_keyword_must_be_macro(self):
        value = bare_expanded("macro f(*, y)", "MacroBareSplatParameter")
        value["anchor_origin"]["token_event"] = token_event(0, "def", "IDENT")
        self.assertRejected(value, "invalid structural anchor")

    def test_expanded_bare_splat_keyword_after_the_star_is_refused(self):
        value = bare_expanded()
        value["anchor_origin"]["token_event"] = token_event(6, "def", "IDENT")
        self.assertRejected(value, "anchor does not precede witnesses")

    def test_expanded_bare_splat_keyword_in_another_mode_is_refused(self):
        value = bare_expanded()
        value["anchor_origin"]["token_event"]["lexical_mode"] = "Iyi"
        self.assertRejected(value, "invalid structural anchor")

    def test_expanded_bare_splat_guard_from_another_input_is_refused(self):
        value = bare_expanded()
        value["anchor_origin"]["expansion_guard"] = "sha256:" + "0" * 64
        self.assertRejected(value, "structural witnesses use different inputs")

    def test_expanded_bare_star_without_its_own_event_is_refused(self):
        value = bare_expanded()
        value["witnesses"][0]["event"] = None
        self.assertRejected(value, "invalid structural witness provenance")

    def test_expanded_bare_comma_without_its_own_event_is_refused(self):
        value = bare_expanded()
        value["witnesses"][1]["event"] = None
        self.assertRejected(value, "invalid structural witness provenance")

    def test_expanded_bare_comma_claim_writer_is_refused(self):
        value = bare_expanded()
        value["witnesses"][1]["event"]["byte_parts"] = [astanchor(7, 8, written(0, "Def", "keyword"))]
        self.assertRejected(value, "invalid structural witness provenance")

    def test_rendered_text_of_a_bare_splat_must_be_empty(self):
        value = bare_written()
        value["rendered_text"] = "x"
        self.assertRejected(value, "derived structural rendering differs")

    def test_producer_context_of_a_bare_splat_must_be_parameter(self):
        value = bare_written()
        value["producer_context"] = "local_reference"
        self.assertRejected(value, "derived structural rendering differs")


if __name__ == "__main__":
    unittest.main(verbosity=2)
