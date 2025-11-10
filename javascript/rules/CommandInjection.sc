import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object CommandInjectionRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    // 借鉴CodeQL CommandInjectionCustomizations的Sink定义
    val cmdSinks = cpg.call.l.filter { call =>
      // child_process methods
      call.name.matches("exec|execSync|spawn|spawnSync|execFile|execFileSync|fork") ||
      call.methodFullName.contains("child_process") ||
      // Shell execution
      call.code.contains("shell: true") ||
      // Process execution libraries
      call.methodFullName.matches(".*\\.(exec|spawn|run|execute)") ||
      // System calls
      call.name.matches("system|popen")
    }
    
    val userSources = getExpressRequestSources(cpg)
    
    cmdSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasCommandSanitization(sink, cpg)) {
          val sinkFile = sink.file.name.headOption.getOrElse("unknown")
          val sinkLine = sink.lineNumber.getOrElse(0)
          
          val key = s"$sinkFile:$sinkLine:command-injection"
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
            
            val pathJson = s"""{
  "ruleId": "javascript/command-injection",
  "severity": "CRITICAL",
  "vulnerability": {"file": "$sinkFile", "line": $sinkLine, "code": "${DataFlowUtils.escapeJson(sink.code)}"},
  "context": [$contextJson]
}"""
            
            results += pathJson
          }
        }
      }
    }
    
    results.toList
  }
  
  def hasCommandSanitization(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                            cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val code = sink.code.toLowerCase
    
    // 借鉴CodeQL CommandInjectionSanitizer
    val sanitizerPatterns = List(
      "shellquote", "shell-escape", "shlex", "escape-shell-arg",
      "sanitize", "validate", "whitelist", "allowlist"
    )
    
    sanitizerPatterns.exists(code.contains) ||
    // 检查数组参数（相对安全）
    sink.argument.exists(_.code.startsWith("["))
  }
  
  def getExpressRequestSources(cpg: io.shiftleft.codepropertygraph.Cpg): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    // Express请求属性访问: req.query.name, req.body.username 等
    val expressSources = cpg.call.name("<operator>.fieldAccess").l.filter { call =>
      call.argument.order(1).code.headOption.exists(_.matches("req\\.(query|body|params|headers|cookies)"))
    }
    
    // 命令行参数 - 命令注入特有的源
    val argvSources = cpg.call.l.filter(_.code.matches("process\\.argv.*"))
    
    expressSources ++ argvSources
  }
}
