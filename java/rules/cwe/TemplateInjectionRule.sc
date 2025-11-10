import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-094: 模板注入规则 - 移除复杂防护检测
object TemplateInjectionRule {
  
  def sinkNode(cpg: io.shiftleft.codepropertygraph.Cpg, kind: String, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    (
      // Velocity模板
      safeCalls.filter(c =>
        c.methodFullName.contains("VelocityEngine") && c.name == "evaluate"
      ) ++

      // Freemarker模板
      safeCalls.filter(c =>
        c.methodFullName.contains("Template") && c.name == "process"
      ) ++

      // Thymeleaf模板
      safeCalls.filter(c =>
        c.methodFullName.contains("TemplateEngine") && c.name == "process"
      ) ++

      // Spring Expression Language (SpEL)
      safeCalls.filter(c =>
        c.methodFullName.contains("ExpressionParser") && c.name == "parseExpression"
      ) ++

      // MVEL表达式
      safeCalls.filter(c =>
        c.methodFullName.contains("MVEL") && Set("eval", "executeExpression").contains(c.name)
      ) ++

      // OGNL表达式
      safeCalls.filter(c =>
        c.methodFullName.contains("Ognl") && c.name == "getValue"
      )
    ).l
  }
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, sources: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    implicit val engineContext: EngineContext = EngineContext()
    
    val sinks = sinkNode(cpg, "template-injection", safeCalls)
    val flowPaths = sinks.reachableByFlows(sources).l
    
    val groupedFlows = flowPaths.groupBy(flow => {
      val sink = flow.elements.last
      val loc = sink.location
      (loc.filename, loc.lineNumber.getOrElse(1))
    }).map { case (_, flows) =>
      flows.sortBy(f => f.elements.last.location.lineNumber.getOrElse(1)).head
    }
    
    groupedFlows.map { flow =>
      val sink = flow.elements.last
      val sinkLoc = sink.location
      val allElements = flow.elements.toList
      val pathElements = if (allElements.length <= 5) {
        allElements
      } else {
        // 显示：第1步 + 第2步 + 中间1步 + 倒数第2步 + 最后1步
        val mid = allElements(allElements.length / 2)
        List(allElements(0), allElements(1), mid, allElements(allElements.length - 2), allElements.last)
      }
      val path = pathElements.map { node =>
        val loc = node.location
        (loc.filename, loc.lineNumber.getOrElse(1), node.code)
      }
      
      JsonlHelper.formatFinding(
        rule = "template-injection",
        severity = "critical",
        file = sinkLoc.filename,
        line = sinkLoc.lineNumber.getOrElse(1),
        message = "模板注入风险: 用户输入未经验证直接用于模板引擎",
        sinkCode = sink.code,
        dataflowPath = path
      )
    }.toList
  }
}
