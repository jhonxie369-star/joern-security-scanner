import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object OpenRedirectRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    val redirectSinks = cpg.call.l.filter { call =>
      (call.name == "redirect" && 
       call.methodFullName.contains("express")) ||
      (call.name.matches("writeHead|setHeader") && 
       call.argument.code.exists(_.toLowerCase.contains("location"))) ||
      call.code.matches(".*location\\.(href|replace|assign).*") ||
      call.code.contains("window.location") ||
      call.code.contains("document.location") ||
      (call.name.matches("write|writeln") && 
       call.argument.code.exists(_.toLowerCase.contains("refresh"))) ||
      call.name.matches("sendRedirect|forward")
    }
    
    val userSources = cpg.call.l.filter { call =>
      // Express请求属性访问
      call.name == "<operator>.fieldAccess" && 
      call.argument.order(1).code.headOption.exists(_.matches("req\\.(query|body|params|headers|cookies)"))
    }
    
    redirectSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasUrlValidation(sink, cpg)) {
          val sinkFile = sink.file.name.headOption.getOrElse("unknown")
          val sinkLine = sink.lineNumber.getOrElse(0)
          
          val key = s"$sinkFile:$sinkLine:open-redirect"
          if (!seen.contains(key)) {
            seen += key
            
            val pathNodes = DataFlowUtils.buildRealDataFlowPath(source, sink, cpg)
            
            val contextItems = scala.collection.mutable.ListBuffer[(String, Int, String)]()
            contextItems += ((source.file.name.headOption.getOrElse("unknown"), source.lineNumber.getOrElse(0), DataFlowUtils.escapeJson(source.code)))
            
            pathNodes.foreach { node =>
              contextItems += ((node._1, node._2, DataFlowUtils.escapeJson(node._3)))
            }
            
            val contextJson = contextItems.zipWithIndex.map { case ((file, line, code), index) =>
              s"""{"step":${index+1},"file":"$file","line":$line,"code":"$code"}"""
            }.mkString(",")
            
            results += s"""{"rule":"open-redirect","severity":"medium","file":"$sinkFile","line":$sinkLine,"message":"开放重定向风险","sink_code":"${DataFlowUtils.escapeJson(sink.code)}","dataflow_path":[$contextJson]}"""
          }
        }
      }
    }
    
    results.toList
  }
  
  def hasUrlValidation(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                      cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val code = sink.code.toLowerCase
    
    // 借鉴CodeQL UrlRedirectSanitizer
    val validationPatterns = List(
      "startswith", "endswith", "includes", "indexof", "match", "test",
      "url.parse", "new url", "validator.isurl",
      "whitelist", "allowlist", "domain", "hostname",
      "same-origin", "cors", "referer"
    )
    
    validationPatterns.exists(code.contains)
  }
  
  def isRelativeUrl(sink: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    // 检查是否强制使用相对URL
    val args = sink.argument.l
    args.exists { arg =>
      val code = arg.code
      code.startsWith("\"/") || code.startsWith("'/") ||
      code.contains("path.join") || code.contains("path.resolve")
    }
  }
}
