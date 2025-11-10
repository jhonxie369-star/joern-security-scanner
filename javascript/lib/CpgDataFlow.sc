// 基于Joern CPG的真正数据流分析
// 利用Joern的图遍历和reachableBy能力

object CpgDataFlow {
  
  // 使用Joern的reachableBy进行数据流分析
  def findDataFlowPaths(sources: List[io.shiftleft.codepropertygraph.generated.nodes.Call], 
                        sinks: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    
    sinks.foreach { sink =>
      // 使用Joern的reachableBy查找能到达sink的所有节点
      val reachableNodes = sink.reachableBy(cpg.all).l
      
      sources.foreach { source =>
        if (reachableNodes.contains(source)) {
          val fileName = sink.file.name.headOption.getOrElse("unknown")
          val lineNumber = sink.lineNumber.getOrElse(0)
          val sourceFile = source.file.name.headOption.getOrElse("unknown")
          val sourceLine = source.lineNumber.getOrElse(0)
          
          results += s"$fileName:$lineNumber - ${sink.code} (数据流来源: $sourceFile:$sourceLine - ${source.code})"
        }
      }
    }
    
    results.toList
  }
  
  // 使用Joern的数据依赖分析
  def findDataDependencies(targetCall: io.shiftleft.codepropertygraph.generated.nodes.Call): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    
    // 获取目标调用的所有数据依赖
    val dataDeps = targetCall.reachableBy(cpg.all.where(_.isInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Identifier])).l
    
    dataDeps.foreach { dep =>
      val fileName = dep.file.name.headOption.getOrElse("unknown")
      val lineNumber = dep.lineNumber.getOrElse(0)
      results += s"$fileName:$lineNumber - ${dep.code}"
    }
    
    results.toList
  }
  
  // 使用Joern的控制流分析
  def findControlFlowPaths(source: io.shiftleft.codepropertygraph.generated.nodes.Call,
                          sink: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    // 检查控制流可达性
    val cfgNodes = source.method.cfgNode.reachableBy(sink.method.cfgNode).l
    cfgNodes.nonEmpty
  }
  
  // 使用Joern的变量数据流跟踪
  def traceVariableFlow(varName: String): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    
    // 找到所有该变量的定义点
    val definitions = cpg.identifier.name(varName).referencingIdentifiers.l
    
    // 找到所有该变量的使用点
    val usages = cpg.identifier.name(varName).l
    
    usages.foreach { usage =>
      // 对每个使用点，查找能到达它的定义点
      val reachableDefs = usage.reachableBy(definitions).l
      
      reachableDefs.foreach { defn =>
        val defFile = defn.file.name.headOption.getOrElse("unknown")
        val defLine = defn.lineNumber.getOrElse(0)
        val useFile = usage.file.name.headOption.getOrElse("unknown")
        val useLine = usage.lineNumber.getOrElse(0)
        
        results += s"变量流: $defFile:$defLine -> $useFile:$useLine ($varName)"
      }
    }
    
    results.toList
  }
  
  // 使用Joern的方法调用链分析
  def findCallChains(startMethod: String, endMethod: String): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    
    val startCalls = cpg.call.name(startMethod).l
    val endCalls = cpg.call.name(endMethod).l
    
    endCalls.foreach { endCall =>
      val reachableFromStart = endCall.reachableBy(startCalls).l
      
      reachableFromStart.foreach { startCall =>
        val startFile = startCall.file.name.headOption.getOrElse("unknown")
        val startLine = startCall.lineNumber.getOrElse(0)
        val endFile = endCall.file.name.headOption.getOrElse("unknown")
        val endLine = endCall.lineNumber.getOrElse(0)
        
        results += s"调用链: $startFile:$startLine ($startMethod) -> $endFile:$endLine ($endMethod)"
      }
    }
    
    results.toList
  }
  
  // 使用Joern的参数传递分析
  def traceArgumentFlow(functionName: String, argIndex: Int): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    
    // 找到函数调用
    val calls = cpg.call.name(functionName).l
    
    calls.foreach { call =>
      // 获取指定位置的参数
      val args = call.argument.l
      if (args.length > argIndex) {
        val targetArg = args(argIndex)
        
        // 跟踪参数的数据流来源
        val argSources = targetArg.reachableBy(cpg.identifier).l
        
        argSources.foreach { source =>
          val sourceFile = source.file.name.headOption.getOrElse("unknown")
          val sourceLine = source.lineNumber.getOrElse(0)
          val callFile = call.file.name.headOption.getOrElse("unknown")
          val callLine = call.lineNumber.getOrElse(0)
          
          results += s"参数流: $sourceFile:$sourceLine -> $callFile:$callLine (参数$argIndex: ${targetArg.code})"
        }
      }
    }
    
    results.toList
  }
  
  // 使用Joern的污点分析
  def performTaintAnalysis(sources: List[String], sinks: List[String]): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    
    // 找到所有源点
    val sourceNodes = sources.flatMap { sourceName =>
      cpg.call.name(s".*$sourceName.*").l ++
      cpg.identifier.name(s".*$sourceName.*").l
    }
    
    // 找到所有汇聚点
    val sinkNodes = sinks.flatMap { sinkName =>
      cpg.call.name(s".*$sinkName.*").l
    }
    
    // 对每个汇聚点，检查是否有污点数据流入
    sinkNodes.foreach { sink =>
      val taintedInputs = sink.reachableBy(sourceNodes).l
      
      taintedInputs.foreach { taintSource =>
        val sourceFile = taintSource.file.name.headOption.getOrElse("unknown")
        val sourceLine = taintSource.lineNumber.getOrElse(0)
        val sinkFile = sink.file.name.headOption.getOrElse("unknown")
        val sinkLine = sink.lineNumber.getOrElse(0)
        
        results += s"污点流: $sourceFile:$sourceLine (${taintSource.code}) -> $sinkFile:$sinkLine (${sink.code})"
      }
    }
    
    results.toList
  }
  
  // 使用Joern的AST遍历查找模式
  def findSecurityPatterns(): Map[String, List[String]] = {
    val patterns = scala.collection.mutable.Map[String, scala.collection.mutable.ListBuffer[String]]()
    
    // SQL注入模式：字符串拼接 + SQL执行
    val sqlConcats = cpg.call.name("\\+").where(_.argument.isLiteral.code(".*SELECT|INSERT|UPDATE|DELETE.*")).l
    sqlConcats.foreach { concat =>
      // 查找使用这个拼接结果的SQL执行调用
      val sqlExecs = cpg.call.name("query|execute|exec").reachableBy(List(concat)).l
      
      sqlExecs.foreach { exec =>
        val file = exec.file.name.headOption.getOrElse("unknown")
        val line = exec.lineNumber.getOrElse(0)
        patterns.getOrElseUpdate("sql-injection", scala.collection.mutable.ListBuffer()) += 
          s"$file:$line - SQL拼接后执行: ${exec.code}"
      }
    }
    
    // XSS模式：用户输入 + DOM操作
    val userInputs = cpg.call.name(".*req\\.(query|body|params).*").l
    userInputs.foreach { input =>
      val domOps = cpg.call.name("innerHTML|outerHTML|document\\.write").reachableBy(List(input)).l
      
      domOps.foreach { domOp =>
        val file = domOp.file.name.headOption.getOrElse("unknown")
        val line = domOp.lineNumber.getOrElse(0)
        patterns.getOrElseUpdate("xss", scala.collection.mutable.ListBuffer()) += 
          s"$file:$line - 用户输入直接输出到DOM: ${domOp.code}"
      }
    }
    
    // 命令注入模式：用户输入 + 命令执行
    userInputs.foreach { input =>
      val cmdExecs = cpg.call.name("exec|spawn|execSync").reachableBy(List(input)).l
      
      cmdExecs.foreach { cmdExec =>
        val file = cmdExec.file.name.headOption.getOrElse("unknown")
        val line = cmdExec.lineNumber.getOrElse(0)
        patterns.getOrElseUpdate("command-injection", scala.collection.mutable.ListBuffer()) += 
          s"$file:$line - 用户输入用于命令执行: ${cmdExec.code}"
      }
    }
    
    patterns.mapValues(_.toList).toMap
  }
  
  // 使用Joern的数据流摘要
  def getDataFlowSummary(): Map[String, Any] = {
    val totalNodes = cpg.all.size
    val callNodes = cpg.call.size
    val identifierNodes = cpg.identifier.size
    val methodNodes = cpg.method.size
    
    Map(
      "totalNodes" -> totalNodes,
      "callNodes" -> callNodes,
      "identifierNodes" -> identifierNodes,
      "methodNodes" -> methodNodes,
      "avgCallsPerMethod" -> if (methodNodes > 0) callNodes.toDouble / methodNodes else 0.0
    )
  }
}
