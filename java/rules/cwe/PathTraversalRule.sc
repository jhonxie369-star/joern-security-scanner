import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-022: 路径遍历规则 - 对标CodeQL TaintedPathQuery
object PathTraversalRule {
  
  // 对标CodeQL的sinkNode(this, "path-injection")
  def sinkNode(cpg: io.shiftleft.codepropertygraph.Cpg, kind: String, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    val (sinks, _) = JavaModelParser.parseModels(kind)
    
    sinks.flatMap { sink =>
      // 使用传入的安全调用列表
      safeCalls.filter { call =>
        val fullName = call.methodFullName
        // 更宽松的匹配 - 处理构造函数
        if (sink.methodName == "<init>") {
          fullName.contains(sink.packageName) && fullName.contains(sink.className) && fullName.contains("init")
        } else {
          fullName.contains(sink.packageName) && 
          fullName.contains(sink.className) && 
          fullName.contains(sink.methodName)
        }
      }.flatMap { call =>
        // 对标CodeQL的input解释逻辑
        interpretInput(call, sink.input)
      }
    }
  }
  
  // 对标CodeQL的input解释器
  private def interpretInput(call: io.shiftleft.codepropertygraph.generated.nodes.Call, input: String) = {
    input match {
      case "Argument[this]" => 
        // 对标CodeQL的this参数处理
        List(call.receiver).flatten
      case input if input.startsWith("Argument[") =>
        // 对标CodeQL的Argument[n]处理
        val argPattern = """Argument\[(\d+)\]""".r
        input match {
          case argPattern(index) => 
            val argIndex = index.toInt
            if (argIndex == 0) List(call.receiver).flatten
            else call.argument.drop(argIndex - 1).headOption.toList
          case _ => List(call)
        }
      case "ReturnValue" =>
        // 对标CodeQL的返回值处理
        List(call)
      case _ => 
        // 默认情况
        List(call)
    }
  }
  
  // 对标CodeQL的ActiveThreatModelSource
  def getActiveThreatModelSources(cpg: io.shiftleft.codepropertygraph.Cpg, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    (
      // HTTP请求参数 - 对标CodeQL的RemoteFlowSource
      safeCalls.filter(c => 
        c.methodFullName.contains("HttpServletRequest") && 
        Set("getParameter", "getHeader", "getQueryString", "getRequestURI").contains(c.name)
      ) ++
      
      // Spring注解参数 - 对标CodeQL的SpringController sources
      cpg.method.parameter.filter(p => 
        p.annotation.name.exists(_.matches(".*(RequestParam|PathVariable|RequestBody).*"))
      ) ++
      
      // 文件上传 - 对标CodeQL的FileUpload sources
      safeCalls.filter(c => 
        c.methodFullName.contains("MultipartFile") && 
        Set("getOriginalFilename", "getName").contains(c.name)
      )
    ).l
  }
  
  // 对标CodeQL的PathInjectionSanitizer
  def getPathInjectionSanitizers(cpg: io.shiftleft.codepropertygraph.Cpg, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    (
      // 路径规范化 - 对标CodeQL的canonicalization
      safeCalls.filter(c => 
        c.methodFullName.contains("getCanonicalPath") ||
        c.methodFullName.contains("normalize") ||
        c.methodFullName.contains("toRealPath")
      ) ++
      
      // 路径验证 - 对标CodeQL的validation guards
      safeCalls.filter(c =>
        c.methodFullName.contains("startsWith") ||
        c.methodFullName.contains("contains") && 
        c.argument.code.exists(_.matches(".*[a-zA-Z0-9/_-]+.*"))
      )
    ).l
  }
  
  // 对标CodeQL的TaintedPathFlow.flowPath(source, sink)
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, sources: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    println(s"🔍 PathTraversal检测开始，sources: ${sources.size}, safeCalls: ${safeCalls.size}")
    
    implicit val engineContext: EngineContext = EngineContext()
    
    // 获取path-injection的sink节点
    println("🔍 获取path-injection sinks...")
    val sinks = sinkNode(cpg, "path-injection", safeCalls)
    println(s"🔍 找到 ${sinks.size} 个path-injection sinks")
    
    // CodeQL风格：直接使用污点追踪引擎，依赖内置的sanitizer处理
    println("🔍 开始全局污点追踪（CodeQL风格）...")
    val flowPaths = sinks.reachableByFlows(sources).l
    println(s"🔍 找到 ${flowPaths.size} 个数据流")
    
    // 直接格式化结果并去重
    println("🔍 开始格式化结果...")
    val groupedFlows = flowPaths.groupBy(flow => {
      val sink = flow.elements.last
      val loc = sink.location
      (loc.filename, loc.lineNumber.getOrElse(1))
    }).map { case (_, flows) =>
      flows.sortBy(f => f.elements.last.location.lineNumber.getOrElse(1)).head
    }
    
    
    val results = groupedFlows.map { flow =>
      val sink = flow.elements.last
      val sinkLoc = sink.location
      val allElements = flow.elements.toList
      val pathElements = if (allElements.length <= 5) {
        allElements
      } else {
        // 显示：第1步 + 第2步 + 中间1步 + 倒数第2步 + 最后1步
        val mid = allElements(allElements.length / 2)
        List(allElements(0), allElements(1), mid, allElements(allElements.length - 2), allElements.last)
      }
      val path = pathElements.map { node =>
        val loc = node.location
        (loc.filename, loc.lineNumber.getOrElse(1), node.code)
      }
      
      JsonlHelper.formatFinding(
        rule = "path-traversal",
        severity = "high",
        file = sinkLoc.filename,
        line = sinkLoc.lineNumber.getOrElse(1),
        message = "路径遍历风险: 用户输入未经验证直接用于文件路径",
        sinkCode = sink.code,
        dataflowPath = path
      )
    }.toList
    println(s"🔍 PathTraversal检测完成，返回 ${results.size} 个去重后结果")
    
    results
  }
  
  // 对标CodeQL的详细路径报告
  def getPathProblemReport(cpg: io.shiftleft.codepropertygraph.Cpg, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    implicit val engineContext: EngineContext = EngineContext()
    
    val sources = getActiveThreatModelSources(cpg, safeCalls)
    val sinks = sinkNode(cpg, "path-injection", safeCalls)
    
    // 对标CodeQL的PathGraph报告
    sinks.reachableBy(sources).l.map { sink =>
      val reachingSources = sources.filter(source => 
        sink.reachableBy(List(source)).nonEmpty
      )
      
      val location = sink.location
      Map(
        "sink" -> sink.code,
        "location" -> s"${location.filename}:${location.lineNumber}",
        "sources" -> reachingSources.map(_.code),
        "message" -> "This path depends on a user-provided value",
        "cwe" -> "CWE-022",
        "severity" -> "HIGH"
      )
    }
  }
}
