import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object UnsafeDeserializationRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    val deserializationSinks = cpg.call.l.filter { call =>
      (call.name == "parse" && call.code.contains("JSON")) ||
      call.name == "eval" ||
      call.name == "Function" ||
      call.name.matches("unserialize|deserialize|loads") ||
      call.name.matches("runInThisContext|runInNewContext|runInContext") ||
      (call.name.matches("load|safeLoad") && 
       (call.code.contains("yaml") || call.code.contains("YAML"))) ||
      call.name.matches("loads|load") && 
       (call.code.contains("pickle") || call.code.contains("marshal")) ||
      (call.name.matches("compile|template") && 
       call.methodFullName.matches(".*\\.(handlebars|mustache|lodash)"))
    }
    
    val userSources = cpg.call.l.filter { call =>
      call.code.contains("req.") && (call.code.contains("body") || call.code.contains("query") || call.code.contains("params"))
    }
    
    deserializationSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasDeserializationProtection(sink, cpg)) {
          val sinkFile = sink.file.name.headOption.getOrElse("unknown")
          val sinkLine = sink.lineNumber.getOrElse(0)
          
          val key = s"$sinkFile:$sinkLine:unsafe-deserialization"
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
            
            val severity = if (sink.name.matches("eval|Function")) "critical" else "high"
            
            results += s"""{"rule":"unsafe-deserialization","severity":"$severity","file":"$sinkFile","line":$sinkLine,"message":"不安全的反序列化","sink_code":"${DataFlowUtils.escapeJson(sink.code)}","dataflow_path":[$contextJson]}"""
          }
        }
      }
    }
    
    results.toList
  }
  
  def hasDeserializationProtection(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                                  cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val code = sink.code.toLowerCase
    
    // 借鉴CodeQL DeserializationSanitizer
    val protectionPatterns = List(
      "reviver", "replacer", "schema", "validate",
      "safeyaml", "safeload", "safe-eval", "safer-eval",
      "sanitize", "whitelist", "allowlist"
    )
    
    protectionPatterns.exists(code.contains)
  }
  
  def hasSafeDeserialization(sink: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val code = sink.code.toLowerCase
    val safePatterns = List(
      "reviver", "replacer",
      "safeyaml", "safeload",
      "schema", "validate"
    )
    safePatterns.exists(code.contains)
  }
}
