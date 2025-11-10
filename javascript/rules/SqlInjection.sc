import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object SqlInjectionRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, modelsPath: String = "models"): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    // 加载YAML威胁模型
    val (sinks, sources, sanitizers) = JavaScriptModelParser.parseModels("sql-injection", modelsPath)
    println(s"✓ 加载模型: ${sinks.size} sinks, ${sources.size} sources, ${sanitizers.size} sanitizers")
    
    // 使用YAML定义的Sinks
    val sqlSinks = cpg.call.l.filter { call =>
      JavaScriptModelParser.matchesSink(call, sinks) ||
      // 保留基础检测避免漏报
      call.name.matches("query|execute|run|all|get|each|prepare")
    }
    
    // 使用YAML定义的Sources + Express服务端请求源
    val userSources = cpg.call.l.filter { call =>
      JavaScriptModelParser.matchesSource(call, sources) ||
      // Express请求属性访问: req.query.name, req.body.username 等
      (call.name == "<operator>.fieldAccess" && 
       call.argument.order(1).code.headOption.exists(_.matches("req\\.(query|body|params|headers|cookies)")))
    }
    
    sqlSinks.foreach { sink =>
      userSources.foreach { source =>
        // 真正的图可达性检查
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty) {
          // 使用YAML定义的Sanitizers检查
          val hasSanitizer = reachablePaths.exists { node =>
            node.isCall && JavaScriptModelParser.matchesSanitizer(node.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call], sanitizers)
          }
          
          if (!hasSanitizer) {
            val sinkFile = sink.file.name.headOption.getOrElse("unknown")
            val sinkLine = sink.lineNumber.getOrElse(0)
            
            val key = s"$sinkFile:$sinkLine:sql-injection"
            if (!seen.contains(key)) {
              seen += key
              
              // 真正的DDG路径追踪
              val pathNodes = buildRealDataFlowPath(source, sink, cpg)
              
              val contextItems = scala.collection.mutable.ListBuffer[(String, Int, String)]()
              contextItems += ((source.file.name.headOption.getOrElse("unknown"), source.lineNumber.getOrElse(0), escapeJson(source.code)))
              
              pathNodes.foreach { node =>
                contextItems += ((node._1, node._2, escapeJson(node._3)))
              }
              
              val contextJson = contextItems.zipWithIndex.map { case ((file, line, code), index) =>
                s"""{"step":${index+1},"file":"$file","line":$line,"code":"$code"}"""
              }.mkString(",")
              
              results += s"""{"rule":"sql-injection","severity":"high","file":"$sinkFile","line":$sinkLine,"message":"SQL注入风险: 用户输入未经验证直接用于SQL查询","sink_code":"${escapeJson(sink.code)}","dataflow_path":[$contextJson]}"""
            }
          }
        }
      }
    }
    
    results.toList
  }
  
  // 真正的DDG数据流路径追踪
  def buildRealDataFlowPath(source: io.shiftleft.codepropertygraph.generated.nodes.Call, 
                            sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                            cpg: io.shiftleft.codepropertygraph.Cpg): List[(String, Int, String)] = {
    val path = scala.collection.mutable.ListBuffer[(String, Int, String)]()
    
    // 使用Joern的DDG追踪中间节点
    val ddgNodes = sink.reachableBy(List(source)).l
    
    ddgNodes.foreach { node =>
      if (node != source && node != sink) {
        val file = node.file.name.headOption.getOrElse("unknown")
        val line = node.lineNumber.getOrElse(0)
        val code = node.code
        
        if (line > 0 && code.nonEmpty) {
          path += ((file, line, code))
        }
      }
    }
    
    path.toList.sortBy(_._2)
  }
  
  def escapeJson(s: String): String = {
    s.replace("\\", "\\\\")
     .replace("\"", "\\\"")
     .replace("\n", "\\n")
     .replace("\r", "\\r")
     .replace("\t", "\\t")
  }
}
