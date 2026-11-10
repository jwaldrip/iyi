#!/usr/bin/env python3
"""Behavioural and adversarial tests for the OperatorName derivation (contract C-OP).

Every production is checked in both anchor classes (Written and Expanded) through
the comparator's own entry points: derived_name, origin, name_value and
checked_origin. Tampered spans, kinds, rendered data, anchors, graph depth and
macro byte parts must each be refused with its exact message.

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


def spliced_index(covering=(3, 4), claim=None):
    """Expanded a[1] whose ] comes from one spliced claim (A1); the [ anchor carries the same claim."""
    claim = written(0) if claim is None else claim
    value = operator("Index", "a[1]", [(1, "[", "[", "Whole"), (3, "]", "]", "Whole")], "[]",
                     "method_name", "expanded")
    value["anchor_origin"]["token_event"]["byte_parts"] = [astanchor(1, 2, claim)]
    value["witnesses"][1]["event"]["byte_parts"] = [astanchor(covering[0], covering[1], claim)]
    return value


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


class ProductionTests(unittest.TestCase):
    """Positive cases: every production in both anchor classes, through every entry point."""

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
        two_token = index_assign()
        self.assertEqual(frames.derived_name(two_token, 0)[1], b"[]=")
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


class RejectionTests(unittest.TestCase):
    """Adversarial cases: each mutation is refused with its exact message."""

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

    # Later expanded witnesses: macro byte parts and event identity.

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

    def test_later_witness_with_an_ast_anchor_part_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["byte_parts"] = [
            {"kind": "AstAnchor", "start_offset": 5, "end_offset": 6, "emitter_origin": None,
             "source_origin": written(5)},
        ]
        self.assertRejected(value, "invalid operator witness provenance")

    def test_later_witness_with_a_non_raw_producer_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["byte_parts"][0]["producer"] = "ArtifactSemanticRenderer"
        self.assertRejected(value, "invalid operator witness provenance")

    def test_later_witness_part_misplaced_from_the_span_is_refused(self):
        value = index_assign("expanded")
        value["witnesses"][2]["event"]["byte_parts"] = [generated(6, 7)]
        self.assertRejected(value, "invalid operator witness provenance")

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


class SplicedWitnessTests(unittest.TestCase):
    """Amendment A1: a later expanded witness may carry one spliced AstAnchor; mixed provenance is refused."""

    def assertRejected(self, value, message):
        with self.assertRaises(ValueError) as caught:
            frames.derived_name(value, 0)
        self.assertEqual(str(caught.exception), message)

    def test_spliced_witness_covering_its_token_exactly_is_accepted(self):
        self.assertEqual(frames.derived_name(spliced_index((3, 4)), 0), (("Name", "method_name"), b"[]"))

    def test_spliced_witness_with_a_wider_covering_range_is_accepted(self):
        self.assertEqual(frames.derived_name(spliced_index((2, 5)), 0)[1], b"[]")

    def test_spliced_witness_may_carry_a_macro_directive_emitter(self):
        value = spliced_index()
        value["witnesses"][1]["event"]["byte_parts"][0]["emitter_origin"] = written(0, "MacroDirective", "expression")
        self.assertEqual(frames.derived_name(value, 0)[1], b"[]")

    def test_spliced_witness_reaches_origin_name_value_and_checked_origin(self):
        value = spliced_index()
        self.assertEqual(frames.origin(value), ("Name", "method_name"))
        self.assertEqual(frames.name_value({"kind": "Derived", "origin": value}, 0), b"[]")
        self.assertEqual(frames.checked_origin(spliced_index()), ("Name", "method_name"))

    def test_generated_then_spliced_parts_are_mixed_and_refused(self):
        value = spliced_index()
        value["witnesses"][1]["event"]["byte_parts"] = [generated(3, 4, "MacroTemplate"),
                                                        astanchor(3, 4, written(0))]
        self.assertRejected(value, "mixed operator witness provenance")

    def test_spliced_then_generated_parts_are_mixed_and_refused(self):
        value = spliced_index()
        value["witnesses"][1]["event"]["byte_parts"] = [astanchor(3, 4, written(0)),
                                                        generated(3, 4, "MacroTemplate")]
        self.assertRejected(value, "mixed operator witness provenance")

    def test_two_spliced_claims_on_one_witness_are_refused(self):
        value = spliced_index()
        value["witnesses"][1]["event"]["byte_parts"] = [astanchor(3, 4, written(0)), astanchor(3, 4, written(0))]
        self.assertRejected(value, "invalid operator witness provenance")

    def test_spliced_source_origin_other_than_witness_zero_is_refused(self):
        value = spliced_index()
        value["witnesses"][1]["event"]["byte_parts"] = [astanchor(3, 4, written(9))]
        self.assertRejected(value, "invalid operator witness provenance")

    def test_spliced_source_origin_differing_in_role_is_refused(self):
        value = spliced_index()
        value["witnesses"][1]["event"]["byte_parts"] = [astanchor(3, 4, written(0, "Name", "method_name"))]
        self.assertRejected(value, "invalid operator witness provenance")

    def test_spliced_witness_needs_a_spliced_witness_zero(self):
        value = spliced_index()
        value["anchor_origin"]["token_event"]["byte_parts"] = [generated(1, 2, "MacroTemplate")]
        self.assertRejected(value, "invalid operator witness provenance")

    def test_spliced_claim_not_covering_the_token_is_refused(self):
        for covering in ((3, 3), (0, 3), (4, 6)):
            with self.subTest(covering=covering):
                self.assertRejected(spliced_index(covering), "invalid operator witness provenance")

    def test_spliced_witness_emitter_outside_macro_directive_is_refused(self):
        value = spliced_index()
        value["witnesses"][1]["event"]["byte_parts"][0]["emitter_origin"] = written(0, "Call", "method")
        self.assertRejected(value, "invalid operator witness provenance")



if __name__ == "__main__":
    unittest.main(verbosity=2)
