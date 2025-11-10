import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-023: 文件路径遍历规则 - 对标CodeQL FilePathTraversal
object FilePathTraversalRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, sources: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    implicit val engineContext: EngineContext = EngineContext()
    
    // 获取file-path-injection的sink节点
    val sinks = sinkNode(cpg, "file-path-injection", safeCalls)
    
    // 对标CodeQL的污点追踪
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
        rule = "file-path-traversal",
        severity = "high",
        file = sinkLoc.filename,
        line = sinkLoc.lineNumber.getOrElse(1),
        message = "文件路径遍历风险: 用户输入未经验证直接用于文件路径",
        sinkCode = sink.code,
        dataflowPath = path
      )
    }.toList
  }
  
  // 对标CodeQL的sinkNode(this, "file-path-injection")
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
      case "Argument[0]" => call.argument.headOption.toList
      case "Argument[1]" => call.argument.drop(1).headOption.toList
      case "Argument[this]" => call.receiver.headOption.toList
      case _ => List()
    }
  }
}
