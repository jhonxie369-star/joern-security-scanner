import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-611: XXE规则 - 移除复杂防护检测
object XxeRule {
  
  def sinkNode(cpg: io.shiftleft.codepropertygraph.Cpg, kind: String, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    (
      // DocumentBuilder.parse
      safeCalls.filter(c =>
        c.methodFullName.contains("DocumentBuilder") && c.name == "parse"
      ) ++

      // SAXParser.parse
      safeCalls.filter(c =>
        c.methodFullName.contains("SAXParser") && c.name == "parse"
      ) ++

      // XMLReader.parse
      safeCalls.filter(c =>
        c.methodFullName.contains("XMLReader") && c.name == "parse"
      ) ++

      // Transformer.transform
      safeCalls.filter(c =>
        c.methodFullName.contains("Transformer") && c.name == "transform"
      ) ++

      // SchemaFactory.newSchema
      safeCalls.filter(c =>
        c.methodFullName.contains("SchemaFactory") && c.name == "newSchema"
      ) ++

      // Unmarshaller.unmarshal
      safeCalls.filter(c =>
        c.methodFullName.contains("Unmarshaller") && c.name == "unmarshal"
      )
    ).l
  }
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, sources: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    implicit val engineContext: EngineContext = EngineContext()
    
    val sinks = sinkNode(cpg, "xxe", safeCalls)
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
        rule = "xxe",
        severity = "high",
        file = sinkLoc.filename,
        line = sinkLoc.lineNumber.getOrElse(1),
        message = "XXE风险: XML外部实体注入漏洞",
        sinkCode = sink.code,
        dataflowPath = path
      )
    }.toList
  }
}
