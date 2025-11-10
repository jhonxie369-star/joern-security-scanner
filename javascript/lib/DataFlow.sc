// JavaScript数据流分析库 - 基于CodeQL威胁模型
// 提供Source和Sink的识别能力，配合reachableBy使用

import $file.ThreatModels

object DataFlow {
  
  // 加载威胁模型
  lazy val (sourceModels, sinkModels, summaryModels) = {
    val modelsDir = "models"
    ThreatModels.loadThreatModels(modelsDir)
  }
  
  // 获取HTTP请求参数源点（对标CodeQL的RemoteFlowSource）
  def getRemoteSources(): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    cpg.call.where(_.name(".*req\\.(query|body|params|headers).*")).l ++
    cpg.identifier.where(_.name(".*req\\.(query|body|params).*")).l
  }
  
  // 获取环境变量源点
  def getEnvironmentSources(): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    cpg.call.where(_.name("process.env")).l ++
    getSourcesByKind("environment")
  }
  
  // 获取特定类型的源点（基于威胁模型）
  def getSourcesByKind(kind: String): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    cpg.call.l.filter { call =>
      ThreatModels.matchesSourceModel(call, sourceModels).contains(kind)
    }
  }
  
  // SQL注入汇聚点（对标CodeQL的SqlInjectionSink）
  def getSqlSinks(): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    getSinksByKind("sql-injection") ++
    cpg.call.where(_.name("query|execute|run")).l
  }
  
  // XSS汇聚点
  def getXssSinks(): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    getSinksByKind("xss") ++
    cpg.call.where(_.name("innerHTML|outerHTML|document\\.write|res\\.send")).l
  }
  
  // 命令注入汇聚点
  def getCommandSinks(): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    getSinksByKind("command-injection") ++
    cpg.call.where(_.name("exec|spawn|execSync|spawnSync")).l
  }
  
  // 获取特定类型的汇聚点（基于威胁模型）
  def getSinksByKind(kind: String): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    cpg.call.l.filter { call =>
      ThreatModels.matchesSinkModel(call, sinkModels).contains(kind) ||
      ThreatModels.getDangerousFunctions().get(call.name).contains(kind)
    }
  }
  
  // 获取调用的详细信息
  def getCallInfo(call: io.shiftleft.codepropertygraph.generated.nodes.Call): String = {
    val fileName = call.file.name.headOption.getOrElse("unknown")
    val lineNumber = call.lineNumber.getOrElse(0)
    val code = call.code
    s"$fileName:$lineNumber - $code"
  }
  
  // 获取威胁模型统计信息
  def getThreatModelStats(): Map[String, Int] = {
    Map(
      "sourceModels" -> sourceModels.length,
      "sinkModels" -> sinkModels.length,
      "summaryModels" -> summaryModels.length,
      "totalModels" -> (sourceModels.length + sinkModels.length + summaryModels.length)
    )
  }
}
