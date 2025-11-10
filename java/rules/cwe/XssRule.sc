import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-079: XSS规则 - 移除复杂防护检测
object XssRule {
  
  def sinkNode(cpg: io.shiftleft.codepropertygraph.Cpg, kind: String, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    val (sinks, _) = JavaModelParser.parseModels(kind)
    
    sinks.flatMap { sink =>
      safeCalls.filter { call =>
        val fullName = call.methodFullName
        fullName.contains(sink.packageName) && 
        fullName.contains(sink.className) && 
        fullName.contains(sink.methodName)
      }.flatMap { call =>
        interpretInput(call, sink.input)
      }
    }
  }
  
  private def interpretInput(call: io.shiftleft.codepropertygraph.generated.nodes.Call, input: String) = {
    input match {
      case "Argument[this]" => List(call.receiver).flatten
      case input if input.startsWith("Argument[") =>
        val argPattern = """Argument\[(\d+)\]""".r
        input match {
          case argPattern(index) => 
            val argIndex = index.toInt
            if (argIndex == 0) List(call.receiver).flatten
            else call.argument.drop(argIndex - 1).headOption.toList
          case _ => List(call)
        }
      case _ => List(call)
    }
  }
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, sources: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    implicit val engineContext: EngineContext = EngineContext()
    
    val sinks = sinkNode(cpg, "xss", safeCalls)
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
        rule = "xss",
        severity = "high",
        file = sinkLoc.filename,
        line = sinkLoc.lineNumber.getOrElse(1),
        message = "XSS风险: 用户输入未经转义直接输出到HTML",
        sinkCode = sink.code,
        dataflowPath = path
      )
    }.toList
  }
}
