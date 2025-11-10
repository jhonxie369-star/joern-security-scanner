import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object PathTraversalRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, modelsPath: String = "models"): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    // 加载YAML威胁模型
    val (sinks, sources, sanitizers) = JavaScriptModelParser.parseModels("path-injection", modelsPath)
    println(s"✓ 加载模型: ${sinks.size} sinks, ${sources.size} sources, ${sanitizers.size} sanitizers")
    
    // 使用YAML定义的Sinks + 基础检测
    val fileSinks = cpg.call.l.filter { call =>
      JavaScriptModelParser.matchesSink(call, sinks) ||
      call.name.matches("readFile|writeFile|readFileSync|writeFileSync|open|createReadStream|createWriteStream")
    }
    
    // 使用YAML定义的Sources + Express请求源
    val userSources = cpg.call.l.filter { call =>
      JavaScriptModelParser.matchesSource(call, sources) ||
      // Express请求属性访问
      (call.name == "<operator>.fieldAccess" && 
       call.argument.order(1).code.headOption.exists(_.matches("req\\.(query|body|params|headers|cookies)")))
    }
    
    fileSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty) {
          // 使用YAML定义的Sanitizers检查
          val hasSanitizer = reachablePaths.exists { node =>
            node.isCall && JavaScriptModelParser.matchesSanitizer(node.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call], sanitizers)
          }
          
          if (!hasSanitizer) {
            val sinkFile = sink.file.name.headOption.getOrElse("unknown")
            val sinkLine = sink.lineNumber.getOrElse(0)
            
            val key = s"$sinkFile:$sinkLine:path-traversal"
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
              
              results += s"""{"rule":"path-traversal","severity":"high","file":"$sinkFile","line":$sinkLine,"message":"路径遍历风险","sink_code":"${DataFlowUtils.escapeJson(sink.code)}","dataflow_path":[$contextJson]}"""
            }
          }
        }
      }
    }
    
    results.toList
  }
}
