import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object PrototypePollutionRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    val protoSinks = cpg.call.l.filter { call =>
      (call.name.matches("assign|merge|extend|defaults|defaultsDeep") &&
       (call.methodFullName.contains("Object") || 
        call.code.contains("_") || call.code.contains("$"))) ||
      call.code.contains("__proto__") ||
      call.code.contains(".prototype.") ||
      call.code.contains("constructor.prototype") ||
      (call.name == "parse" && call.code.contains("JSON"))
    }
    
    val userSources = cpg.call.l.filter { call =>
      // Express请求属性访问
      call.name == "<operator>.fieldAccess" && 
      call.argument.order(1).code.headOption.exists(_.matches("req\\.(query|body|params|headers|cookies)"))
    }
    
    protoSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasPrototypePollutionProtection(sink, cpg)) {
          val sinkFile = sink.file.name.headOption.getOrElse("unknown")
          val sinkLine = sink.lineNumber.getOrElse(0)
          
          val key = s"$sinkFile:$sinkLine:prototype-pollution"
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
            
            results += s"""{"rule":"prototype-pollution","severity":"high","file":"$sinkFile","line":$sinkLine,"message":"原型污染风险","sink_code":"${DataFlowUtils.escapeJson(sink.code)}","dataflow_path":[$contextJson]}"""
          }
        }
      }
    }
    
    results.toList
  }
  
  def hasPrototypePollutionProtection(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                                     cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val code = sink.code.toLowerCase
    val protectionPatterns = List(
      "hasownproperty", "object.hasownproperty",
      "whitelist", "allowlist", "sanitize", "validate",
      "object.freeze", "object.seal",
      "json-schema", "ajv"
    )
    protectionPatterns.exists(code.contains)
  }
}
