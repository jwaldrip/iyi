require "json"
require "./diagnostic_type"

module Iyi::DiagnosticEnvironment
  # Describes the semantic lexical set. The emitted closure layout and its
  # ordered parent chain remain codegen's independent responsibility.
  def self.snapshot(vars : Iyi::MetaVars, current_scope : Iyi::ASTNode, lexical_scope : Iyi::Type?) : JSON::Any?
    lexical_type = lexical_scope ? Iyi::DiagnosticType.identity(lexical_scope) : nil
    return nil if lexical_scope && !lexical_type
    self_type = nil
    bindings = [] of {String, JSON::Any}
    vars.each do |name, var|
      return nil unless name == var.name
      type = var.type? || return nil
      type_identity = Iyi::DiagnosticType.identity(type) || return nil
      if name == "self"
        self_type = type_identity
        next
      end
      binding = var.diagnostic_origin.as?(Iyi::DiagnosticOrigin::Synthetic) || return nil
      return nil unless binding.valid_for_binding?
      scope = var.context || return nil
      scope_identity = case scope
                       when Iyi::Def
                         if scope.same?(current_scope)
                           JSON.parse(%({"kind":"current_scope"}))
                         else
                           scope_origin = scope.diagnostic_origin || return nil
                           specialization = scope.diagnostic_specialization_json || return nil
                           JSON.parse(JSON.build do |json|
                             json.object do
                               json.field "kind", "def"
                               json.field "origin", scope_origin
                               json.field "specialization", specialization
                             end
                           end)
                         end
                       when Iyi::Block
                         if scope.same?(current_scope)
                           JSON.parse(%({"kind":"current_scope"}))
                         else
                           scope_origin = scope.diagnostic_origin || return nil
                           specialization = scope.diagnostic_specialization_json || return nil
                           JSON.parse(JSON.build do |json|
                             json.object do
                               json.field "kind", "block"
                               json.field "origin", scope_origin
                               json.field "specialization", specialization
                             end
                           end)
                         end
                       when Iyi::Program
                         JSON.parse(%({"kind":"program"}))
                       else
                         return nil
                       end
      entry = JSON.parse(JSON.build do |json|
        json.object do
          json.field "name", name
          json.field "binding_origin", binding
          json.field "scope", scope_identity
          json.field "type", type_identity
          json.field "mutable", var.mutably_closured?
          json.field "closured", var.closured?
          json.field "assigned", var.assigned_to?
        end
      end)
      bindings << {"#{binding.to_json}\u0000#{name}", entry}
    end
    bindings.sort_by!(&.[0])
    bindings.each_cons_pair { |left, right| return nil if left[0] == right[0] }
    JSON.parse(JSON.build do |json|
      json.object do
        json.field "self_type", self_type
        json.field "lexical_scope_type", lexical_type
        json.field "bindings", bindings.map(&.[1])
      end
    end)
  end
end
