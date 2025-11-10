import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

// 参考CodeQL js/file-access-to-http规则
object FileAccessToHttpRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    // HTTP响应sinks
    val httpSinks = cpg.call.l.filter { call =>
      // Express.js响应
      call.name.matches("send|json|end|write") &&
      call.methodFullName.contains("express") ||
      // HTTP模块响应
      call.name.matches("write|end") &&
      call.code.contains("res.") ||
      // 文件下载
      call.name == "download" ||
      call.name == "sendFile"
    }
    
    // 文件读取sources
    val fileSources = cpg.call.l.filter { call =>
      // 文件系统读取
      call.name.matches("readFile|readFileSync|createReadStream") ||
      // 文件统计
      call.name.matches("stat|statSync|lstat|lstatSync") ||
      // 目录读取
      call.name.matches("readdir|readdirSync")
    }
    
    httpSinks.foreach { sink =>
      fileSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasFileAccessControl(source, sink, cpg)) {
          val sinkFile = sink.file.name.headOption.getOrElse("unknown")
          val sinkLine = sink.lineNumber.getOrElse(0)
          
          val key = s"$sinkFile:$sinkLine:file-access-to-http"
          if (!seen.contains(key)) {
            seen += key
            
            val propagationNode = findPropagationNode(source, sink, cpg)
            
            val contextItems = scala.collection.mutable.ListBuffer[(String, Int, String)]()
            contextItems += ((source.file.name.headOption.getOrElse("unknown"), source.lineNumber.getOrElse(0), escapeJson(source.code)))
            
            propagationNode.foreach { prop =>
              contextItems += ((prop._1, prop._2, escapeJson(prop._3)))
            }
            
            val contextJson = contextItems.zipWithIndex.map { case ((file, line, code), index) =>
              s"""{"order": ${index + 1}, "file": "$file", "line": $line, "code": "$code"}"""
            }.mkString(",")
            
            val pathJson = s"""{
  "ruleId": "javascript/file-access-to-http",
  "severity": "MEDIUM",
  "vulnerability": {"file": "$sinkFile", "line": $sinkLine, "code": "${escapeJson(sink.code)}"},
  "context": [$contextJson]
}"""
            
            results += pathJson
          }
        }
      }
    }
    
    results.toList
  }
  
  def hasFileAccessControl(source: io.shiftleft.codepropertygraph.generated.nodes.Call,
                          sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                          cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    
    val sourceCode = source.code.toLowerCase
    val sinkCode = sink.code.toLowerCase
    
    // 访问控制模式
    val accessControlPatterns = List(
      "auth", "permission", "role", "acl",
      "whitelist", "allowlist", "sanitize",
      "path.resolve", "path.normalize"
    )
    
    accessControlPatterns.exists(sourceCode.contains) ||
    accessControlPatterns.exists(sinkCode.contains)
  }
  
  def findPropagationNode(source: io.shiftleft.codepropertygraph.generated.nodes.Call, 
                         sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                         cpg: io.shiftleft.codepropertygraph.Cpg): Option[(String, Int, String)] = {
    
    val sourceFile = source.file.name.headOption.getOrElse("")
    val sinkFile = sink.file.name.headOption.getOrElse("")
    val sourceLine = source.lineNumber.getOrElse(0)
    val sinkLine = sink.lineNumber.getOrElse(0)
    
    if (sourceFile == sinkFile && sourceLine < sinkLine && (sinkLine - sourceLine) <= 5) {
      val assignments = cpg.assignment.l.filter { assign =>
        val assignLine = assign.lineNumber.getOrElse(0)
        val assignFile = assign.file.name.headOption.getOrElse("")
        assignFile == sourceFile && assignLine > sourceLine && assignLine < sinkLine
      }.sortBy(_.lineNumber.getOrElse(0))
      
      assignments.headOption.map { assign =>
        (
          assign.file.name.headOption.getOrElse("unknown"),
          assign.lineNumber.getOrElse(0),
          assign.code.replaceAll("\\s+", " ").trim
        )
      }
    } else {
      None
    }
  }
  
  def escapeJson(str: String): String = {
    str.replace("\\", "\\\\")
       .replace("\"", "\\\"")
       .replace("\n", "\\n")
       .replace("\r", "\\r")
       .replaceAll("\\s+", " ")
       .trim
  }
  
  def getRuleInfo(): Map[String, Any] = Map(
    "id" -> "javascript/file-access-to-http",
    "name" -> "文件访问到HTTP响应",
    "severity" -> "MEDIUM",
    "cwe" -> List("CWE-200"),
    "description" -> "检测未授权的文件访问暴露到HTTP响应，参考CodeQL规则"
  )
}
