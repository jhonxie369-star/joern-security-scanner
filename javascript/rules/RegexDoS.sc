import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object RegexDoSRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    val regexUsages = cpg.call.l.filter { call =>
      call.name == "RegExp" ||
      (call.name.matches("match|replace|search|split|test|exec") &&
       call.methodFullName.contains("String")) ||
      call.code.contains("new RegExp") ||
      (call.name.matches("isEmail|isURL|matches") &&
       call.methodFullName.contains("validator")) ||
      (call.name.matches("get|post|put|delete") &&
       call.argument.code.exists(_.contains("*")))
    }
    
    val userSources = cpg.call.l.filter { call =>
      call.code.contains("req.") && (call.code.contains("body") || call.code.contains("query") || call.code.contains("params"))
    }
    
    regexUsages.foreach { usage =>
      val regexPatterns = extractRegexPatterns(usage)
      
      regexPatterns.foreach { pattern =>
        if (isVulnerableRegex(pattern)) {
          userSources.foreach { source =>
            val reachablePaths = usage.reachableBy(List(source)).l
            
            if (reachablePaths.nonEmpty) {
              val usageFile = usage.file.name.headOption.getOrElse("unknown")
              val usageLine = usage.lineNumber.getOrElse(0)
              
              val key = s"$usageFile:$usageLine:redos"
              if (!seen.contains(key)) {
                seen += key
                
                val pathNodes = DataFlowUtils.buildRealDataFlowPath(source, usage, cpg)
                
                val contextItems = scala.collection.mutable.ListBuffer[(String, Int, String)]()
                contextItems += ((source.file.name.headOption.getOrElse("unknown"), source.lineNumber.getOrElse(0), DataFlowUtils.escapeJson(source.code)))
                
                pathNodes.foreach { node =>
                  contextItems += ((node._1, node._2, DataFlowUtils.escapeJson(node._3)))
                }
                
                pathNodes.foreach { node =>
                  contextItems += ((node._1, node._2, DataFlowUtils.escapeJson(node._3)))
                }
                
                val contextJson = contextItems.zipWithIndex.map { case ((file, line, code), index) =>
                  s"""{"step":${index+1},"file":"$file","line":$line,"code":"$code"}"""
                }.mkString(",")
                
                results += s"""{"rule":"redos","severity":"medium","file":"$usageFile","line":$usageLine,"message":"正则表达式拒绝服务风险","sink_code":"${DataFlowUtils.escapeJson(usage.code)}","regex_pattern":"${DataFlowUtils.escapeJson(pattern)}","dataflow_path":[$contextJson]}"""
              }
            }
          }
        }
      }
    }
    
    results.toList
  }
  
  def isVulnerableRegex(pattern: String): Boolean = {
    // 借鉴CodeQL的ReDoS检测模式
    
    // 1. 嵌套量词 - (a+)+, (a*)*
    val nestedQuantifiers = """(\([^)]*[+*]\)[+*])""".r
    if (nestedQuantifiers.findFirstIn(pattern).isDefined) return true
    
    // 2. 交替与重复 - (a|a)*
    val alternationWithRepeat = """(\([^)]*\|[^)]*\)[+*])""".r
    if (alternationWithRepeat.findFirstIn(pattern).isDefined) return true
    
    // 3. 指数级回溯模式
    val exponentialBacktrack = List(
      """(\.\*){2,}""", // 多个 .*
      """(\.\+){2,}""", // 多个 .+
      """\([^)]*\+[^)]*\+[^)]*\)""", // 组内多个+
      """\([^)]*\*[^)]*\*[^)]*\)""", // 组内多个*
      """(\w\+)+""", // 单词字符重复
      """([a-z]+)+""" // 字符类重复
    )
    
    exponentialBacktrack.exists(p => pattern.matches(s".*$p.*"))
  }
  
  def extractRegexPatterns(call: io.shiftleft.codepropertygraph.generated.nodes.Call): List[String] = {
    val patterns = scala.collection.mutable.ListBuffer[String]()
    call.argument.l.foreach { arg =>
      val code = arg.code
      val regexLiteralPattern = """/([^/]+)/[gimuy]*""".r
      regexLiteralPattern.findAllMatchIn(code).foreach { m =>
        patterns += m.group(1)
      }
      
      // 匹配字符串中的正则表达式
      val stringPattern = """"([^"]+)"""".r
      stringPattern.findAllMatchIn(code).foreach { m =>
        val pattern = m.group(1)
        if (pattern.contains("*") || pattern.contains("+") || pattern.contains("{")) {
          patterns += pattern
        }
      }
    }
    
    patterns.toList
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
}
