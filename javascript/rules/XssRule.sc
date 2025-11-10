import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

// 参考CodeQL js/xss和js/dom-based-xss规则
object XssRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    val htmlSinks = getHtmlSinks(cpg)
    val urlSinks = getUrlSinks(cpg)
    val jquerySinks = getJQuerySinks(cpg)
    val reflectedXssSinks = getReflectedXssSinks(cpg)
    
    val userSources = getXssSources(cpg)
    
    // HTML sinks - any tainted value
    htmlSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasSanitizer(source, sink, cpg) && isCallbackTainted(sink, source, reachablePaths)) {
          addResult(results, seen, source, sink, cpg, "DOM-based XSS (HTML sink)")
        }
      }
    }
    
    // URL sinks - only if prefix is controlled
    urlSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasSanitizer(source, sink, cpg) && isPrefixControlled(source, sink)) {
          addResult(results, seen, source, sink, cpg, "DOM-based XSS (URL sink)")
        }
      }
    }
    
    // jQuery sinks - only if can start with '<'
    jquerySinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasSanitizer(source, sink, cpg) && canStartWithAngleBracket(source)) {
          addResult(results, seen, source, sink, cpg, "DOM-based XSS (jQuery sink)")
        }
      }
    }
    
    // Reflected XSS
    reflectedXssSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasSanitizer(source, sink, cpg)) {
          addResult(results, seen, source, sink, cpg, "Reflected XSS")
        }
      }
    }
    
    results.toList
  }
  
  private def addResult(results: scala.collection.mutable.ListBuffer[String],
                       seen: scala.collection.mutable.Set[String],
                       source: io.shiftleft.codepropertygraph.generated.nodes.Call,
                       sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                       cpg: io.shiftleft.codepropertygraph.Cpg,
                       message: String): Unit = {
    val sinkFile = sink.file.name.headOption.getOrElse("unknown")
    val sinkLine = sink.lineNumber.getOrElse(0)
    
    val key = s"$sinkFile:$sinkLine:xss"
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
      
      results += s"""{"rule":"xss","severity":"high","file":"$sinkFile","line":$sinkLine,"message":"$message","sink_code":"${DataFlowUtils.escapeJson(sink.code)}","dataflow_path":[$contextJson]}"""
    }
  }
  
  private def isCallbackTainted(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                                source: io.shiftleft.codepropertygraph.generated.nodes.Call,
                                pathNodes: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): Boolean = {
    // 对于动态代码执行的 sink，检查回调参数是否在污点路径中
    if (sink.name.matches("setInterval|setTimeout|Function|eval")) {
      val firstArg = sink.argument.order(1).headOption
      
      firstArg match {
        case Some(arg) =>
          // 如果是字面量函数，不是污染的
          if (arg.code.contains("function") || arg.code.contains("=>")) {
            false
          } else {
            // 检查第一个参数是否在污点路径中
            pathNodes.exists(_.code == arg.code)
          }
        case None => true
      }
    } else {
      // 其他 sink 默认认为是污染的
      true
    }
  }
  
  private def isDynamicCodeWithFixedCallback(sink: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    // Filter out setInterval/setTimeout with fixed function callbacks (not dynamic code execution)
    if (sink.name.matches("setInterval|setTimeout")) {
      val firstArg = sink.argument.order(1).headOption
      firstArg.exists { arg =>
        // If first argument is a function expression/arrow function, it's fixed code
        arg.code.contains("function") || arg.code.contains("=>") || arg.code.matches("\\w+")
      }
    } else {
      false
    }
  }
  
  private def hasSanitizer(source: io.shiftleft.codepropertygraph.generated.nodes.Call,
                          sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                          cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val pathNodes = sink.reachableBy(List(source)).l
    
    pathNodes.exists { node =>
      val code = node.code.toLowerCase
      // XSS sanitizers
      code.contains("escape") || code.contains("sanitize") || code.contains("encode") ||
      code.contains("htmlentities") || code.contains("dompurify") || 
      code.contains("validator.escape") || code.contains("he.encode") ||
      code.contains("textcontent") || // textContent is safe (doesn't parse HTML)
      code.contains("innertext") // innerText is safe
    }
  }
  
  private def isPrefixControlled(source: io.shiftleft.codepropertygraph.generated.nodes.Call,
                                sink: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    // For URL sinks, check if the source can control the URL prefix (scheme)
    // This is a simplified check - in reality would need more sophisticated analysis
    val sourceCode = source.code.toLowerCase
    // If source is from URL fragment/search, it's suffix only
    !(sourceCode.contains("location.hash") || sourceCode.contains("location.search"))
  }
  
  private def canStartWithAngleBracket(source: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    // For jQuery sinks, check if value can start with '<'
    // Simplified: assume user input can start with '<' unless proven otherwise
    val sourceCode = source.code
    // If it's a known safe prefix, return false
    !sourceCode.matches(".*['\"]\\s*[^<].*")
  }
  
  def isDomBasedXss(sink: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val domMethods = List("innerHTML", "outerHTML", "insertAdjacentHTML", "location.href")
    domMethods.exists(sink.code.contains)
  }
  
  def hasXssProtection(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                      cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val code = sink.code.toLowerCase
    
    // XSS防护模式
    val protectionPatterns = List(
      "escape", "sanitize", "encode", "htmlentities", 
      "dompurify", "xss", "validator.escape", "he.encode"
    )
    
    protectionPatterns.exists(code.contains)
  }
  
  def getXssSources(cpg: io.shiftleft.codepropertygraph.Cpg): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    // DOM sources
    val domSources = cpg.call.l.filter { call =>
      call.code.contains("location.search") ||
      call.code.contains("location.hash") ||
      call.code.contains("location.href") ||
      call.code.contains("document.URL") ||
      call.code.contains("document.documentURI") ||
      call.code.contains("document.referrer") ||
      call.code.contains("window.name") ||
      call.code.contains("postMessage") ||
      call.code.contains("onmessage") ||
      call.code.contains("localStorage") ||
      call.code.contains("sessionStorage") ||
      call.name.matches("getElementById|querySelector|querySelectorAll") ||
      call.code.contains("WebSocket") ||
      call.code.contains("history.state")
    }
    
    // Server sources - 匹配 req.query.*, req.body.* 等的属性访问
    // 参考 CodeQL: queryRef(request).getAPropertyRead()
    val serverSources = cpg.call.name("<operator>.fieldAccess").l.filter { call =>
      // 第一个参数应该是 req.query, req.body 等
      call.argument.order(1).code.headOption.exists { arg =>
        arg.matches("req\\.(query|body|params|headers|cookies)")
      }
    }
    
    domSources ++ serverSources
  }
  
  def getHtmlSinks(cpg: io.shiftleft.codepropertygraph.Cpg): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    cpg.call.l.filter { call =>
      // DOM manipulation that interprets as HTML
      call.name.matches("innerHTML|outerHTML") ||
      (call.name.matches("write|writeln") && call.code.contains("document")) ||
      call.name == "insertAdjacentHTML" ||
      // jQuery HTML methods (excluding selector-only methods)
      (call.name.matches("html|append|prepend|after|before|replaceWith|wrap|wrapAll|wrapInner") && 
       (call.code.contains("$") || call.code.contains("jQuery"))) ||
      // Angular methods
      call.code.contains("$sce.trustAsHtml") ||
      // Library-specific
      call.name.matches("setInnerHTMLUnsafe|setOuterHTMLUnsafe") ||
      call.code.contains("dangerouslySetInnerHTML")
    }
  }
  
  def getUrlSinks(cpg: io.shiftleft.codepropertygraph.Cpg): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    cpg.call.l.filter { call =>
      // URL manipulation sinks
      call.code.contains("location.href") ||
      call.code.contains("location.replace") ||
      call.code.contains("location.assign") ||
      call.code.contains("window.open") ||
      call.name == "open" && call.code.contains("window")
    }
  }
  
  def getJQuerySinks(cpg: io.shiftleft.codepropertygraph.Cpg): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    cpg.call.l.filter { call =>
      // jQuery $() that can interpret as HTML or selector
      (call.name == "$" || call.code.startsWith("jQuery(")) &&
      call.argument.order(1).code.exists(c => !c.startsWith("\"#") && !c.startsWith("'#"))
    }
  }
  
  def getDomXssSinks(cpg: io.shiftleft.codepropertygraph.Cpg): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    cpg.call.l.filter { call =>
      call.name.matches("innerHTML|outerHTML") ||
      (call.name.matches("write|writeln") && call.code.contains("document")) ||
      call.name == "insertAdjacentHTML" ||
      (call.name.matches("html|append|prepend|after|before|replaceWith") && 
       (call.code.contains("$") || call.code.contains("jQuery"))) ||
      call.code.contains("location.href") ||
      call.code.contains("location.replace") ||
      call.name.matches("eval|setTimeout|setInterval|Function") ||
      call.name == "createElement" && call.argument.code.exists(_.contains("script"))
    }
  }
  
  def getReflectedXssSinks(cpg: io.shiftleft.codepropertygraph.Cpg): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    cpg.call.l.filter { call =>
      // Express response methods
      (call.name.matches("send|json|render|end|write|sendFile|download") && call.code.contains("res.")) ||
      // Template engines
      call.name.matches("render|compile")
    }
  }
}
