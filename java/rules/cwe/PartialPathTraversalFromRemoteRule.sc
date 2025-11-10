import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-023: 远程部分路径遍历规则 - 对标CodeQL PartialPathTraversalFromRemote (@kind path-problem)
object PartialPathTraversalFromRemoteRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, sources: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    implicit val engineContext: EngineContext = EngineContext()
    
    val sinks = getPartialPathTraversalSinks(cpg, safeCalls)
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
        rule = "partial-path-traversal-remote",
        severity = "high",
        file = sinkLoc.filename,
        line = sinkLoc.lineNumber.getOrElse(1),
        message = "远程部分路径遍历: 用户输入用于不完整的路径前缀检查",
        sinkCode = sink.code,
        dataflowPath = path
      )
    }.toList
  }
  
  // 获取部分路径遍历的sink点 - 只检测真正的路径操作
  private def getPartialPathTraversalSinks(cpg: io.shiftleft.codepropertygraph.Cpg, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    safeCalls.filter { call =>
      val methodName = call.methodFullName
      (
        // Path.startsWith() - 明确的路径操作
        (methodName.contains("java.nio.file.Path") && call.name == "startsWith") ||
        // File路径检查后的startsWith
        (methodName.contains("String") && call.name == "startsWith" && isPathValidationContext(call)) ||
        // File.getCanonicalPath() - 但必须用于路径验证
        (methodName.contains("File") && Set("getCanonicalPath", "getAbsolutePath").contains(call.name) && 
         hasSubsequentStartsWithCheck(call))
      )
    }
  }
  
  // 检测是否为路径验证上下文
  private def isPathValidationContext(call: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val surroundingCode = call.inAst.code.mkString(" ").toLowerCase
    val argCode = call.argument.headOption.map(_.code.toLowerCase).getOrElse("")
    
    // 必须是路径相关的验证
    val pathValidationKeywords = Set("allowedpath", "basepath", "rootpath", "safepath", "validpath")
    val hasPathValidation = pathValidationKeywords.exists(keyword => surroundingCode.contains(keyword))
    
    // 参数必须包含路径分隔符
    val hasPathSeparator = argCode.contains("/") || argCode.contains("\\")
    
    // 排除明显的非路径检查
    val nonPathPatterns = Set("http", "charset", "json", "{", ":", "port", "config", "protocol")
    val isNonPath = nonPathPatterns.exists(pattern => argCode.contains(pattern))
    
    hasPathValidation && hasPathSeparator && !isNonPath
  }
  
  // 检测是否有后续的startsWith检查
  private def hasSubsequentStartsWithCheck(call: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    // 检查该调用的结果是否用于startsWith检查
    call.inAst.isCall.name("startsWith").nonEmpty
  }
}
