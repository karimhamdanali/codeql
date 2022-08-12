/**
 * @name TODO
 * @description TODO
 * @kind path-problem
 * @problem.severity error
 * @security-severity TODO
 * @precision high
 * @id swift/tls13-is-not-used
 * @tags security
 *       external/cwe/cwe-757
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.dataflow.FlowSources
import DataFlow::PathGraph

/**
 * TODO
 */
class TLS13IsNotUsedConfig extends TaintTracking::Configuration {
  TLS13IsNotUsedConfig() { this = "TLS13IsNotUsedConfig" }

  override predicate isSink(DataFlow::Node node) {
    exists(AssignExpr assign, MemberRefExpr member, string memberName |
      assign.getSource() = node.asExpr() and
      assign.getDest() = member and
      memberName = member.getMember().(ConcreteVarDecl).getName() and
      (
        memberName = "tlsMinimumSupportedProtocolVersion" or
        memberName = "tlsMinimumSupportedProtocol" or
        memberName = "tlsMaximumSupportedProtocolVersion" or
        memberName = "tlsMaximumSupportedProtocol"
      )
    )
  }

  override predicate isSource(DataFlow::Node node) {
    exists(MethodRefExpr expr, EnumElementDecl enum, string enumName |
      node.asExpr() = expr and
      expr.getMember() = enum and
      enumName = enum.getName() and
      (
        enumName = "TLSv10" or
        enumName = "TLSv11" or
        enumName = "tlsProtocol10" or
        enumName = "tlsProtocol11"
      )
    )
  }
}

from TLS13IsNotUsedConfig config, DataFlow::PathNode sourceNode, DataFlow::PathNode sinkNode
where config.hasFlowPath(sourceNode, sinkNode)
select sinkNode.getNode(), sourceNode, sinkNode,
  "TLS 1.3 should be used (from " + sourceNode.getNode().asExpr().getEnclosingFunction().getName() +
    ")"
