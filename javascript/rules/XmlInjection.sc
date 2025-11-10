import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

// 前端JavaScript XML注入检测 - 重点关注DOM和XSS风险
object XmlInjectionRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    // 前端XML处理的危险sinks
    val xmlSinks = cpg.call.l.filter { call =>
      // DOMParser.parseFromString()
      (call.name == "parseFromString" && 
       call.code.contains("DOMParser")) ||
      // innerHTML with XML content
      (call.name == "innerHTML" && 
       isXmlContent(call)) ||
      // XMLHttpRequest responseXML
      call.code.contains("responseXML") ||
      // jQuery parseXML
      (call.name == "parseXML" && 
       call.code.contains("jQuery")) ||
      // document.createElement with XML
      (call.name == "createElement" && 
       isXmlElement(call))
    }
    
    val userSources = getClientSideSources(cpg)
    
    xmlSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty) {
          val sinkFile = sink.file.name.headOption.getOrElse("unknown")
          val sinkLine = sink.lineNumber.getOrElse(0)
          
          val key = s"$sinkFile:$sinkLine:xml-injection"
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
  "ruleId": "javascript/xml-injection",
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
  
  def isXmlContent(call: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val args = call.argument.l
    args.exists { arg =>
      val code = arg.code.toLowerCase
      code.contains("<") && code.contains(">") && 
      (code.contains("xml") || code.contains("svg") || code.contains("<?"))
    }
  }
  
  def isXmlElement(call: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val args = call.argument.l
    args.exists { arg =>
      val code = arg.code.toLowerCase
      List("svg", "xml", "foreignobject").exists(code.contains)
    }
  }
  
  def getClientSideSources(cpg: io.shiftleft.codepropertygraph.Cpg): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    // 前端用户输入源
    cpg.call.l.filter { call =>
      // URL parameters
      call.code.contains("location.search") ||
      call.code.contains("URLSearchParams") ||
      // Form inputs
      call.code.contains("document.getElementById") ||
      call.code.contains("querySelector") ||
      // Local/Session storage
      call.code.contains("localStorage") ||
      call.code.contains("sessionStorage") ||
      // AJAX responses
      call.code.contains("responseText") ||
      call.code.contains("responseXML") ||
      // Express.js sources (if server-side)
      (call.name == "<operator>.fieldAccess" && 
       call.argument.code.exists(_.matches("req"))) ||
      // PostMessage
      call.code.contains("postMessage")
    }
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
    "id" -> "javascript/xml-injection",
    "name" -> "XML注入漏洞(前端)",
    "severity" -> "MEDIUM",
    "cwe" -> List("CWE-91", "CWE-79"),
    "description" -> "检测前端JavaScript中的XML注入和相关XSS风险"
  )
}
