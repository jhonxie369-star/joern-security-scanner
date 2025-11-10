import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-023: 部分路径遍历规则 - 对标CodeQL PartialPathTraversal (@kind problem)
object PartialPathTraversalRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    
    // 只检测真正的路径前缀检查
    val pathChecks = getRealPathPrefixChecks(cpg, safeCalls)
    
    pathChecks.foreach { call =>
      if (isUnsafePathPrefixCheck(call)) {
        val location = call.location
        
        val jsonResult = JsonlHelper.formatFinding(
          rule = "partial-path-traversal",
          severity = "medium",
          file = location.filename,
          line = location.lineNumber.getOrElse(1),
          message = "部分路径遍历漏洞: 路径前缀检查不完整",
          sinkCode = call.code,
          dataflowPath = List((location.filename, location.lineNumber.getOrElse(1), call.code))
        )
        results += jsonResult
      }
    }
    
    results.toList.distinct
  }
  
  // 获取真正的路径前缀检查
  private def getRealPathPrefixChecks(cpg: io.shiftleft.codepropertygraph.Cpg, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    safeCalls.filter { call =>
      val methodName = call.methodFullName
      (
        // Path.startsWith() - 明确的路径操作
        (methodName.contains("java.nio.file.Path") && call.name == "startsWith") ||
        // File.getCanonicalPath().startsWith() - 文件路径检查
        (methodName.contains("File") && Set("getCanonicalPath", "getAbsolutePath").contains(call.name)) ||
        // String.startsWith() - 但必须是明确的路径上下文
        (methodName.contains("String") && call.name == "startsWith" && isFilePathContext(call))
      )
    }
  }
  
  // 检测是否为文件路径上下文
  private def isFilePathContext(call: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val surroundingCode = call.inAst.code.mkString(" ").toLowerCase
    val argCode = call.argument.headOption.map(_.code.toLowerCase).getOrElse("")
    
    // 必须包含明确的路径关键词
    val pathKeywords = Set("path", "file", "directory", "folder", "upload", "download")
    val hasPathKeyword = pathKeywords.exists(keyword => 
      surroundingCode.contains(keyword) || argCode.contains(keyword)
    )
    
    // 排除明显的非路径检查
    val nonPathPatterns = Set("http", "https", "charset", "json", "{", ":", "port", "config", "20")
    val isNonPath = nonPathPatterns.exists(pattern => argCode.contains(pattern))
    
    hasPathKeyword && !isNonPath && (argCode.contains("/") || argCode.contains("\\"))
  }
  
  // 检测是否为不安全的路径前缀检查
  private def isUnsafePathPrefixCheck(call: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    call.name match {
      case "startsWith" =>
        call.argument.exists { arg =>
          val argCode = arg.code
          argCode.contains("\"") && 
          (argCode.contains("/") || argCode.contains("\\")) &&
          !argCode.endsWith("/\"") && 
          !argCode.endsWith("\\\"") &&
          !argCode.contains("File.separator")
        }
      case _ => false
    }
  }
}
