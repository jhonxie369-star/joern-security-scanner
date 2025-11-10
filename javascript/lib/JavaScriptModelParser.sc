import scala.util.{Try, Success, Failure}
import java.io.File
import io.shiftleft.semanticcpg.language._

case class JsSink(library: String, memberPath: String, kind: String)
case class JsSource(library: String, memberPath: String, kind: String)
case class JsSanitizer(library: String, memberPath: String, kind: String)

object JavaScriptModelParser {

  def parseModels(kind: String, modelsPath: String = "models"): (List[JsSink], List[JsSource], List[JsSanitizer]) = {
    val modelsDir = new File(modelsPath)
    if (!modelsDir.exists()) return (List.empty, List.empty, List.empty)
    
    val sinks = scala.collection.mutable.ListBuffer[JsSink]()
    val sources = scala.collection.mutable.ListBuffer[JsSource]()
    val sanitizers = scala.collection.mutable.ListBuffer[JsSanitizer]()
    
    modelsDir.listFiles().filter(_.getName.endsWith(".yml")).foreach { file =>
      Try {
        val content = scala.io.Source.fromFile(file).mkString
        parseYaml(content, kind, sinks, sources, sanitizers)
      }
    }
    
    (sinks.toList, sources.toList, sanitizers.toList)
  }

  private def parseYaml(content: String, targetKind: String,
                        sinks: scala.collection.mutable.ListBuffer[JsSink],
                        sources: scala.collection.mutable.ListBuffer[JsSource],
                        sanitizers: scala.collection.mutable.ListBuffer[JsSanitizer]): Unit = {
    val lines = content.split("\n")
    var currentSection: String = ""
    var inData = false
    
    lines.foreach { line =>
      val trimmed = line.trim
      
      if (trimmed.contains("extensible: sinkModel")) {
        currentSection = "sink"
        inData = false
      } else if (trimmed.contains("extensible: sourceModel")) {
        currentSection = "source"
        inData = false
      } else if (trimmed.contains("extensible: neutralModel") || trimmed.contains("extensible: sanitizerModel")) {
        currentSection = "sanitizer"
        inData = false
      } else if (trimmed.startsWith("data:")) {
        inData = true
      } else if (inData && trimmed.startsWith("- [")) {
        val data = trimmed.substring(3).replace("]", "").replace("\"", "")
        val parts = data.split("\",\\s*\"").map(_.trim.replace("[", ""))
        
        if (currentSection == "sink" && parts.length >= 3) {
          val kind = parts(2)
          if (kind == targetKind) sinks += JsSink(parts(0), parts(1), kind)
        } else if (currentSection == "source" && parts.length >= 3) {
          val kind = parts(2)
          if (kind == targetKind) sources += JsSource(parts(0), parts(1), kind)
        } else if (currentSection == "sanitizer" && parts.length >= 3) {
          val kind = parts(2)
          if (kind == targetKind) sanitizers += JsSanitizer(parts(0), parts(1), kind)
        }
      } else if (trimmed.startsWith("- addsTo:")) {
        currentSection = ""
        inData = false
      }
    }
  }

  def matchesSink(call: io.shiftleft.codepropertygraph.generated.nodes.Call, sinks: List[JsSink]): Boolean = {
    sinks.exists { sink =>
      val methodName = extractMethodName(sink.memberPath)
      (call.code.contains(sink.library) || call.methodFullName.contains(sink.library)) &&
      (methodName.isEmpty || call.name == methodName || call.methodFullName.contains(methodName))
    }
  }

  def matchesSource(call: io.shiftleft.codepropertygraph.generated.nodes.Call, sources: List[JsSource]): Boolean = {
    sources.exists { source =>
      val methodName = extractMethodName(source.memberPath)
      (call.code.contains(source.library) || call.methodFullName.contains(source.library)) &&
      (methodName.isEmpty || call.name == methodName || call.methodFullName.contains(methodName))
    }
  }

  def matchesSanitizer(call: io.shiftleft.codepropertygraph.generated.nodes.Call, sanitizers: List[JsSanitizer]): Boolean = {
    sanitizers.exists { sanitizer =>
      val methodName = extractMethodName(sanitizer.memberPath)
      (call.code.contains(sanitizer.library) || call.methodFullName.contains(sanitizer.library)) &&
      (methodName.isEmpty || call.name == methodName || call.methodFullName.contains(methodName))
    }
  }

  private def extractMethodName(memberPath: String): String = {
    val memberPattern = """Member\[([^\]]+)\]""".r
    memberPattern.findAllMatchIn(memberPath).toList.lastOption.map(_.group(1)).getOrElse("")
  }
}
