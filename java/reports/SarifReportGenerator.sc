import java.io.{File, PrintWriter}
import java.time.Instant

object SarifReportGenerator {
  
  case class SarifResult(
    ruleId: String,
    message: String,
    level: String,
    uri: String,
    startLine: Int
  )
  
  def generateSarifReport(
    results: Map[String, List[String]], 
    severities: Map[String, String],
    cweMapping: Map[String, List[String]],
    descriptions: Map[String, String],
    projectPath: String,
    outputPath: String
  ): Unit = {
    
    val sarifResults = results.flatMap { case (ruleId, issues) =>
      issues.map(parseIssue(_, ruleId))
    }.toList
    
    val writer = new PrintWriter(new File(outputPath))
    try {
      writer.write(generateSimpleSarif(sarifResults, projectPath))
      println(s"📄 SARIF报告已生成: $outputPath")
    } finally {
      writer.close()
    }
  }
  
  private def parseIssue(issue: String, ruleId: String): SarifResult = {
    val pattern = """(.+):(\d+) - (.+)""".r
    issue match {
      case pattern(file, line, message) =>
        SarifResult(ruleId, message, "error", file, line.toInt)
      case _ =>
        SarifResult(ruleId, issue, "error", "unknown", 1)
    }
  }
  
  private def generateSimpleSarif(results: List[SarifResult], projectPath: String): String = {
    val timestamp = Instant.now().toString
    val resultsJson = results.map { r =>
      val cleanMessage = escapeJson(r.message)
      val cleanUri = escapeJson(r.uri)
      s"""    {
      "ruleId": "${r.ruleId}",
      "message": {"text": "$cleanMessage"},
      "level": "${r.level}",
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "$cleanUri"},
          "region": {"startLine": ${r.startLine}}
        }
      }]
    }"""
    }.mkString(",\n")
    
    val sarifContent = s"""{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Joern Security Scanner",
        "version": "1.0.0"
      }
    },
    "results": [
$resultsJson
    ],
    "properties": {
      "scanTime": "$timestamp",
      "totalIssues": ${results.length}
    }
  }]
}"""
    
    sarifContent
  }
  
  private def escapeJson(str: String): String = {
    str.replace("\\", "\\\\")
       .replace("\"", "\\\"")
       .replace("\n", "\\n")
       .replace("\r", "\\r")
       .replace("\t", "\\t")
  }
}
