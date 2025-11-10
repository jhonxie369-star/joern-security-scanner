import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object SsrfRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, modelsPath: String = "models"): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    // 加载YAML威胁模型
    val (sinks, sources, sanitizers) = JavaScriptModelParser.parseModels("request-forgery", modelsPath)
    println(s"✓ 加载模型: ${sinks.size} sinks, ${sources.size} sources, ${sanitizers.size} sanitizers")
    
    // 使用YAML定义的Sinks + 基础检测
    val httpSinks = cpg.call.l.filter { call =>
      JavaScriptModelParser.matchesSink(call, sinks) ||
      // HTTP 客户端库调用
      (call.name == "fetch") ||
      (call.name.matches("get|post|put|delete|patch|request|head|options") && 
       (call.code.contains("axios") || call.code.contains("http.") || call.code.contains("https.") || 
        call.code.contains("request(") || call.code.contains("got(") || call.code.contains("superagent"))) ||
      call.name == "WebSocket" ||
      call.name.matches("lookup|resolve")
    }
    
    // 使用YAML定义的Sources + Express请求源（服务端输入）
    val userSources = cpg.call.l.filter { call =>
      JavaScriptModelParser.matchesSource(call, sources) ||
      // Express请求属性访问
      (call.name == "<operator>.fieldAccess" && 
       call.argument.order(1).code.headOption.exists(_.matches("req\\.(query|body|params|headers|cookies)")))
    }
    
    httpSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty) {
          // 使用YAML定义的Sanitizers检查
          val hasSanitizer = reachablePaths.exists { node =>
            node.isCall && JavaScriptModelParser.matchesSanitizer(node.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call], sanitizers)
          }
          
          if (!hasSanitizer && !hasSsrfProtection(sink, cpg)) {
            val sinkFile = sink.file.name.headOption.getOrElse("unknown")
            val sinkLine = sink.lineNumber.getOrElse(0)
            
            val key = s"$sinkFile:$sinkLine:ssrf"
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
              
              results += s"""{"rule":"ssrf","severity":"high","file":"$sinkFile","line":$sinkLine,"message":"SSRF风险","sink_code":"${DataFlowUtils.escapeJson(sink.code)}","dataflow_path":[$contextJson]}"""
            }
          }
        }
      }
    }
    
    results.toList
  }
  
  def hasSsrfProtection(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                       cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val code = sink.code.toLowerCase
    
    val protectionPatterns = List(
      "whitelist", "allowlist", "validate", "sanitize",
      "url.parse", "new url", "validator.isurl",
      "startswith", "endswith", "includes", "match",
      "localhost", "127.0.0.1", "0.0.0.0", "internal"
    )
    
    protectionPatterns.exists(code.contains)
  }
}
