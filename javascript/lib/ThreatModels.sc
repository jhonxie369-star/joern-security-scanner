// 威胁模型解析器
// 解析CodeQL风格的威胁模型YAML文件

import java.io.File
import scala.io.Source
import scala.util.{Try, Success, Failure}

object ThreatModels {
  
  case class SourceModel(
    library: String,
    path: String,
    kind: String
  )
  
  case class SinkModel(
    library: String,
    path: String,
    kind: String
  )
  
  case class SummaryModel(
    library: String,
    method: String,
    input: String,
    output: String,
    kind: String
  )
  
  // 解析威胁模型文件
  def loadThreatModels(modelsDir: String): (List[SourceModel], List[SinkModel], List[SummaryModel]) = {
    val sources = scala.collection.mutable.ListBuffer[SourceModel]()
    val sinks = scala.collection.mutable.ListBuffer[SinkModel]()
    val summaries = scala.collection.mutable.ListBuffer[SummaryModel]()
    
    val modelsDirectory = new File(modelsDir)
    if (modelsDirectory.exists() && modelsDirectory.isDirectory) {
      modelsDirectory.listFiles().filter(_.getName.endsWith(".model.yml")).foreach { file =>
        Try {
          val content = Source.fromFile(file).mkString
          parseYamlModel(content, sources, sinks, summaries)
        } match {
          case Success(_) => println(s"✅ 加载威胁模型: ${file.getName}")
          case Failure(e) => println(s"⚠️ 加载威胁模型失败 ${file.getName}: ${e.getMessage}")
        }
      }
    }
    
    (sources.toList, sinks.toList, summaries.toList)
  }
  
  // 简化的YAML解析（针对威胁模型格式）
  def parseYamlModel(
    content: String, 
    sources: scala.collection.mutable.ListBuffer[SourceModel],
    sinks: scala.collection.mutable.ListBuffer[SinkModel], 
    summaries: scala.collection.mutable.ListBuffer[SummaryModel]
  ): Unit = {
    val lines = content.split("\n").map(_.trim).filter(_.nonEmpty)
    var currentSection = ""
    var inDataSection = false
    
    for (line <- lines) {
      if (line.contains("extensible: sourceModel")) {
        currentSection = "source"
        inDataSection = false
      } else if (line.contains("extensible: sinkModel")) {
        currentSection = "sink"
        inDataSection = false
      } else if (line.contains("extensible: summaryModel")) {
        currentSection = "summary"
        inDataSection = false
      } else if (line.startsWith("data:")) {
        inDataSection = true
      } else if (inDataSection && line.startsWith("- [")) {
        // 解析数据行: - ["library", "path", "kind"]
        val dataLine = line.substring(3) // 移除 "- ["
        val parts = parseDataLine(dataLine)
        
        if (parts.length >= 3) {
          currentSection match {
            case "source" =>
              sources += SourceModel(parts(0), parts(1), parts(2))
            case "sink" =>
              sinks += SinkModel(parts(0), parts(1), parts(2))
            case "summary" if parts.length >= 5 =>
              summaries += SummaryModel(parts(0), parts(1), parts(2), parts(3), parts(4))
            case _ =>
          }
        }
      }
    }
  }
  
  // 解析数据行
  def parseDataLine(line: String): Array[String] = {
    // 简化解析：处理 ["lib", "path", "kind"] 格式
    val cleaned = line.replace("[", "").replace("]", "").replace("\"", "")
    cleaned.split(",").map(_.trim)
  }
  
  // 检查调用是否匹配威胁模型
  def matchesSourceModel(call: io.shiftleft.codepropertygraph.generated.nodes.Call, models: List[SourceModel]): Option[String] = {
    val callName = call.name
    val receiverCode = call.receiver.code.headOption.getOrElse("")
    
    models.find { model =>
      // 简化匹配逻辑
      callName.contains(model.library) || 
      receiverCode.contains(model.library) ||
      matchesPath(call, model.path)
    }.map(_.kind)
  }
  
  def matchesSinkModel(call: io.shiftleft.codepropertygraph.generated.nodes.Call, models: List[SinkModel]): Option[String] = {
    val callName = call.name
    val receiverCode = call.receiver.code.headOption.getOrElse("")
    
    models.find { model =>
      callName.contains(model.library) || 
      receiverCode.contains(model.library) ||
      matchesPath(call, model.path)
    }.map(_.kind)
  }
  
  // 简化的路径匹配
  def matchesPath(call: io.shiftleft.codepropertygraph.generated.nodes.Call, path: String): Boolean = {
    val callCode = call.code
    
    // 处理常见的路径模式
    if (path.contains("Member[")) {
      val memberPattern = """Member\[([^\]]+)\]""".r
      memberPattern.findAllMatchIn(path).exists { m =>
        val members = m.group(1).split(",")
        members.exists(member => callCode.contains(member.trim))
      }
    } else {
      callCode.contains(path)
    }
  }
  
  // 获取已知的危险函数
  def getDangerousFunctions(): Map[String, String] = Map(
    // SQL注入相关
    "query" -> "sql-injection",
    "execute" -> "sql-injection", 
    "exec" -> "command-injection",
    "spawn" -> "command-injection",
    
    // XSS相关
    "innerHTML" -> "xss",
    "outerHTML" -> "xss",
    "document.write" -> "xss",
    
    // 文件操作
    "readFile" -> "path-injection",
    "writeFile" -> "path-injection",
    
    // HTTP请求
    "request" -> "ssrf",
    "fetch" -> "ssrf",
    "axios" -> "ssrf",
    
    // 代码执行
    "eval" -> "code-injection",
    "Function" -> "code-injection"
  )
  
  // 获取用户输入源
  def getUserInputSources(): List[String] = List(
    "req.query",
    "req.body", 
    "req.params",
    "req.headers",
    "process.argv",
    "location.search",
    "document.cookie"
  )
}
