import scala.util.{Try, Success, Failure}
import java.io.File

// Java安全模型数据结构
case class JavaSink(
  packageName: String,
  className: String,
  subtypes: Boolean,
  methodName: String,
  signature: String,
  ext: String,
  input: String,
  kind: String,
  provenance: String
)

case class JavaSource(
  packageName: String,
  className: String,
  subtypes: Boolean,
  methodName: String,
  signature: String,
  ext: String,
  output: String,
  kind: String,
  provenance: String
)

// Java模型解析器
object JavaModelParser {
  val javaModelsPath = "java/models"
  
  // 解析指定类型的所有模型
  def parseModels(kind: String): (List[JavaSink], List[JavaSource]) = {
    val sinks = parseSinkModels(kind)
    val sources = parseSourceModels(kind)
    (sinks, sources)
  }
  
  // 解析sink模型 (manual + experimental + generated)
  def parseSinkModels(kind: String): List[JavaSink] = {
    println(s"🔍 查找${kind}类型的sinks...")
    val dirs = List("manual", "experimental", "generated")
    val allSinks = dirs.flatMap { dir =>
      val dirPath = new File(javaModelsPath, dir)
      println(s"🔍 检查目录: ${dirPath.getAbsolutePath}")
      if (dirPath.exists()) {
        val yamlFiles = dirPath.listFiles().filter(_.getName.endsWith(".yml"))
        println(s"🔍 ${dir}目录找到${yamlFiles.length}个YAML文件")
        yamlFiles.flatMap(file => {
          val sinks = parseSinkYaml(file.getAbsolutePath, kind)
          if (sinks.nonEmpty) {
            println(s"🔍 ${file.getName}找到${sinks.size}个${kind}类型sinks")
          }
          sinks
        })
      } else {
        println(s"⚠️ 目录不存在: ${dirPath.getAbsolutePath}")
        List.empty
      }
    }
    println(s"🔍 总共找到${allSinks.size}个${kind}类型sinks")
    allSinks
  }
  
  // 解析source模型 (manual + experimental + generated)
  def parseSourceModels(kind: String): List[JavaSource] = {
    println(s"🔍 查找${kind}类型的sources...")
    val dirs = List("manual", "experimental", "generated")
    val allSources = dirs.flatMap { dir =>
      val dirPath = new File(javaModelsPath, dir)
      println(s"🔍 检查目录: ${dirPath.getAbsolutePath}")
      if (dirPath.exists()) {
        val yamlFiles = dirPath.listFiles().filter(_.getName.endsWith(".yml"))
        println(s"🔍 ${dir}目录找到${yamlFiles.length}个YAML文件")
        yamlFiles.flatMap(file => {
          val sources = parseSourceYaml(file.getAbsolutePath, kind)
          if (sources.nonEmpty) {
            println(s"🔍 ${file.getName}找到${sources.size}个${kind}类型sources")
          }
          sources
        })
      } else {
        println(s"⚠️ 目录不存在: ${dirPath.getAbsolutePath}")
        List.empty
      }
    }
    println(s"🔍 总共找到${allSources.size}个${kind}类型sources")
    allSources
  }
  
  // 解析单个sink YAML文件
  def parseSinkYaml(filePath: String, targetKind: String): List[JavaSink] = {
    Try {
      val content = scala.io.Source.fromFile(filePath).mkString
      val lines = content.split("\n")
      
      val sinks = scala.collection.mutable.ListBuffer[JavaSink]()
      var inSinkModel = false
      
      for (line <- lines) {
        val trimmed = line.trim
        if (trimmed.contains("extensible: sinkModel") || trimmed.contains("extensible: experimentalSinkModel")) {
          inSinkModel = true
        } else if (trimmed.startsWith("extensible:") && !trimmed.contains("sinkModel") && !trimmed.contains("experimentalSinkModel")) {
          inSinkModel = false
        } else if (inSinkModel && trimmed.startsWith("- [")) {
          parseSinkLine(trimmed, targetKind) match {
            case Some(sink) => sinks += sink
            case None => // 跳过不匹配的条目
          }
        }
      }
      sinks.toList
    } match {
      case Success(sinks) => sinks
      case Failure(e) => List.empty
    }
  }
  
  // 解析单个source YAML文件
  def parseSourceYaml(filePath: String, targetKind: String): List[JavaSource] = {
    Try {
      val content = scala.io.Source.fromFile(filePath).mkString
      val lines = content.split("\n")
      
      val sources = scala.collection.mutable.ListBuffer[JavaSource]()
      var inSourceModel = false
      
      for (line <- lines) {
        val trimmed = line.trim
        if (trimmed.contains("extensible: sourceModel") || trimmed.contains("extensible: experimentalSourceModel")) {
          inSourceModel = true
        } else if (trimmed.startsWith("extensible:") && !trimmed.contains("sourceModel") && !trimmed.contains("experimentalSourceModel")) {
          inSourceModel = false
        } else if (inSourceModel && trimmed.startsWith("- [")) {
          parseSourceLine(trimmed, targetKind) match {
            case Some(source) => sources += source
            case None => // 跳过不匹配的条目
          }
        }
      }
      sources.toList
    } match {
      case Success(sources) => sources
      case Failure(e) => List.empty
    }
  }
  
  // 解析sink行数据 - 兼容三种格式
  def parseSinkLine(line: String, targetKind: String): Option[JavaSink] = {
    Try {
      // manual/generated格式: 9个字段
      val pattern9 = """\s*-\s*\[\s*"([^"]+)",\s*"([^"]+)",\s*([^,]+),\s*"([^"]+)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]*)"\s*\]""".r
      // experimental格式: 10个字段  
      val pattern10 = """\s*-\s*\[\s*"([^"]+)",\s*"([^"]+)",\s*([^,]+),\s*"([^"]+)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]*)",\s*"([^"]*)"\s*\]""".r
      
      line match {
        case pattern10(pkg, cls, subtypes, method, sig, ext, input, kind, prov, extra) =>
          if (kind == targetKind) {
            Some(JavaSink(pkg, cls, subtypes.trim.toLowerCase == "true", method, sig, ext, input, kind, prov))
          } else None
        case pattern9(pkg, cls, subtypes, method, sig, ext, input, kind, prov) =>
          if (kind == targetKind) {
            Some(JavaSink(pkg, cls, subtypes.trim.toLowerCase == "true", method, sig, ext, input, kind, prov))
          } else None
        case _ => None
      }
    }.toOption.flatten
  }
  
  // 解析source行数据 - 兼容三种格式  
  def parseSourceLine(line: String, targetKind: String): Option[JavaSource] = {
    Try {
      // manual/generated格式: 8个字段
      val pattern8 = """\s*-\s*\[\s*"([^"]+)",\s*"([^"]+)",\s*([^,]+),\s*"([^"]+)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]+)",\s*"([^"]+)"(?:,\s*"([^"]*)")?\s*\]""".r
      // experimental格式: 10个字段
      val pattern10 = """\s*-\s*\[\s*"([^"]+)",\s*"([^"]+)",\s*([^,]+),\s*"([^"]+)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]*)",\s*"([^"]*)"\s*\]""".r
      
      line match {
        case pattern10(pkg, cls, subtypes, method, sig, ext, output, kind, prov, _) =>
          if (kind == targetKind) {
            Some(JavaSource(pkg, cls, subtypes.trim.toLowerCase == "true", method, sig, ext, output, kind, prov))
          } else None
        case pattern8(pkg, cls, subtypes, method, sig, ext, output, kind, prov) =>
          if (kind == targetKind) {
            Some(JavaSource(pkg, cls, subtypes.trim.toLowerCase == "true", method, sig, ext, output, kind, Option(prov).getOrElse("unknown")))
          } else None
        case _ => None
      }
    }.toOption.flatten
  }
  

}
