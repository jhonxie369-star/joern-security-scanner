import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object CodeInjectionRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    val codeSinks = cpg.call.l.filter { call =>
      call.name.matches("eval|Function") ||
      call.name.matches("setTimeout|setInterval") ||
      call.name.matches("runInThisContext|runInNewContext|runInContext") ||
      (call.name == "Worker" && call.argument.code.exists(_.contains("eval"))) ||
      call.name == "import" ||
      call.name.matches("execScript|executeScript") ||
      (call.name.matches("compile|render") && 
       call.methodFullName.matches(".*\\.(handlebars|mustache|ejs|pug)"))
    }
    
    val userSources = cpg.call.l.filter { call =>
      // Express请求属性访问
      call.name == "<operator>.fieldAccess" && 
      call.argument.order(1).code.headOption.exists(_.matches("req\\.(query|body|params|headers|cookies)"))
    }
    
    codeSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasCodeInjectionProtection(sink, cpg)) {
          val sinkFile = sink.file.name.headOption.getOrElse("unknown")
          val sinkLine = sink.lineNumber.getOrElse(0)
          
          val key = s"$sinkFile:$sinkLine:code-injection"
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
            
            results += s"""{"rule":"code-injection","severity":"critical","file":"$sinkFile","line":$sinkLine,"message":"代码注入风险","sink_code":"${DataFlowUtils.escapeJson(sink.code)}","dataflow_path":[$contextJson]}"""
          }
        }
      }
    }
    
    results.toList
  }
  
  def hasCodeInjectionProtection(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                                cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val code = sink.code.toLowerCase
    
    val protectionPatterns = List(
      "sanitize", "validate", "escape", "whitelist", "allowlist",
      "json.parse", "json.stringify",
      "vm.createcontext"
    )
    
    protectionPatterns.exists(code.contains)
  }
  
  def isSafeExecutionContext(sink: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val code = sink.code.toLowerCase
    code.contains("sandbox") || code.contains("restricted") || 
    code.contains("vm.createcontext") || code.contains("isolate")
  }
}
