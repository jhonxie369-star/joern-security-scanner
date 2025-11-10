//> using file models/JavaModelParser.sc
//> using file rules/JavaSecurityRules.sc

import io.joern.console._
import io.joern.dataflowengineoss.language._
import java.io.{File, PrintWriter}
import java.time.Instant

// JSONL报告生成函数（新增）
def generateJsonlReport(
  results: Map[String, List[String]], 
  severities: Map[String, String],
  cweMapping: Map[String, List[String]],
  descriptions: Map[String, String],
  outputPath: String
): Unit = {
  // 严重程度到CVSS分数的映射
  val severityToCvss = Map(
    "CRITICAL" -> 9.0,
    "HIGH" -> 7.5,
    "MEDIUM" -> 5.0,
    "LOW" -> 3.0
  )
  
  val jsonLines = scala.collection.mutable.ListBuffer[String]()
  val timestamp = java.time.Instant.now().toString
  
  results.foreach { case (ruleId, issues) =>
    issues.foreach { jsonStr =>
      val severity = severities.getOrElse(ruleId, "MEDIUM")
      val cvssScore = severityToCvss.getOrElse(severity, 5.0)
      
      val enhancedJson = jsonStr.replaceFirst(
        "\\}$", 
        s""", "cvss": $cvssScore, "cwe": [${cweMapping.getOrElse(ruleId, List()).map(c => s""""$c"""").mkString(",")}], "description": "${descriptions.getOrElse(ruleId, ruleId)}", "timestamp": "$timestamp"}"""
      )
      jsonLines += enhancedJson
    }
  }
  
  val writer = new PrintWriter(new File(outputPath))
  try {
    jsonLines.foreach(writer.println)
    println(s"📄 JSONL报告已生成: $outputPath")
  } finally {
    writer.close()
  }
}

def escapeJson(str: String): String = {
  str.replace("\\", "\\\\")
     .replace("\"", "\\\"")
     .replace("\n", "\\n")
     .replace("\r", "\\r")
     .replaceAll("\\s+", " ")
     .trim
}

// 简化的SARIF报告生成函数（保留兼容）
def generateSimpleSarif(
  results: Map[String, List[String]], 
  severities: Map[String, String],
  cweMapping: Map[String, List[String]],
  descriptions: Map[String, String],
  projectPath: String,
  outputPath: String
): Unit = {
  import java.io.PrintWriter
  
  val sarifResults = results.flatMap { case (ruleId, issues) =>
    issues.map { issue =>
      // 匹配格式：src/main/java/com/example/VulnerableApp.java:Some(31) - getParameter("id")
      val pattern1 = """(.+):Some\((\d+)\) - (.+)""".r
      // 匹配格式：src/main/java/com/example/VulnerableApp.java:31 - getParameter("id")  
      val pattern2 = """(.+):(\d+) - (.+)""".r
      
      issue match {
        case pattern1(file, line, message) =>
          (ruleId, message, file, line.toInt)
        case pattern2(file, line, message) =>
          (ruleId, message, file, line.toInt)
        case _ =>
          // 如果无法解析，尝试提取基本信息
          val parts = issue.split(" - ", 2)
          if (parts.length == 2) {
            val filePart = parts(0)
            val message = parts(1)
            // 尝试从文件部分提取行号
            val fileLinePattern = """(.+):.*?(\d+).*""".r
            filePart match {
              case fileLinePattern(file, line) =>
                (ruleId, message, file, line.toInt)
              case _ =>
                (ruleId, issue, "unknown", 1)
            }
          } else {
            (ruleId, issue, "unknown", 1)
          }
      }
    }
  }.toList
  
  val timestamp = Instant.now().toString
  
  // 使用规则内部的严重程度机制
  val ruleSeverities = JavaSecurityRules.getRuleSeverities()
  
  // 严重程度到CVSS分数的映射
  val severityToCvss = Map(
    "CRITICAL" -> "9.0",
    "HIGH" -> "7.0", 
    "MEDIUM" -> "5.0",
    "LOW" -> "3.0"
  )
  
  // 严重程度到SARIF级别的映射
  val severityToLevel = Map(
    "CRITICAL" -> "error",
    "HIGH" -> "error",
    "MEDIUM" -> "warning", 
    "LOW" -> "note"
  )
  
  val resultsJson = sarifResults.map { case (ruleId, message, file, line) =>
    // 完整的JSON字符串转义
    def escapeJson(str: String): String = {
      str.replace("\\", "\\\\")
         .replace("\"", "\\\"")
         .replace("\n", "\\n")
         .replace("\r", "\\r")
         .replace("\t", "\\t")
         .replace("\b", "\\b")
         .replace("\f", "\\f")
         .replaceAll("[\u0000-\u001F\u007F-\u009F]", "") // 移除所有控制字符
    }
    
    val cleanMessage = escapeJson(message)
    val cleanFile = escapeJson(file)
    
    val severity = ruleSeverities.getOrElse(ruleId, "MEDIUM")
    val level = severityToLevel.getOrElse(severity, "warning")
    val cvssScore = severityToCvss.getOrElse(severity, "5.0")
    
    s"""    {
      "ruleId": "$ruleId",
      "message": {"text": "$cleanMessage"},
      "level": "$level",
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "$cleanFile"},
          "region": {"startLine": $line}
        }
      }],
      "properties": {
        "security-severity": "$cvssScore"
      }
    }"""
  }.mkString(",\n")
  
  val sarifContent = s"""{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Joern Security Scanner",
        "version": "1.0.0",
        "informationUri": "https://github.com/joernio/joern"
      }
    },
    "results": [
$resultsJson
    ],
    "properties": {
      "scanTime": "$timestamp",
      "projectPath": "$projectPath",
      "totalIssues": ${sarifResults.length}
    }
  }]
}"""
  
  val writer = new PrintWriter(new File(outputPath))
  try {
    writer.write(sarifContent)
    println(s"📄 SARIF报告已生成: $outputPath")
  } finally {
    writer.close()
  }
}

@main def execMain(projectPath: String, reportPath: String = ""): Unit = {
  println("=== Java安全扫描器 ===")
  println("基于Joern的Java代码安全分析")
  println(s"📁 扫描项目: $projectPath")

  if (!new File(projectPath).exists) {
    println(s"❌ 项目路径不存在: $projectPath")
    System.exit(1)
  }

  // 创建或加载CPG
  println(s"🔨 为项目创建CPG...")
  
  // 提取项目名称（路径的最后一个目录名）
  val projectName = new File(projectPath).getName.replaceAll("[^a-zA-Z0-9_-]", "_")
  val binPath = s"${projectName}.bin"
  
  // 构建joern-parse命令，指定语言为JAVASRC
  val parseCmd = s"joern-parse $projectPath --output $binPath --language JAVASRC"
  println(s"🔧 执行: $parseCmd")
  
  // 执行joern-parse命令
  import scala.sys.process._
  val result = parseCmd.!
  if (result != 0) {
    println("❌ CPG创建失败")
    return
  }
  
  // 加载预构建的CPG
  importCpg(binPath)

  println(s"\n🔍 开始Java安全扫描...")
  val startTime = System.currentTimeMillis()

  // 使用新的基于kind的扫描方法 - 每个规则使用自己的污点源
  val results = JavaSecurityRules.scanJavaProject(cpg, projectPath, Set.empty[String])
  val severities = JavaSecurityRules.getRuleSeverities()
  val cweMapping = JavaSecurityRules.getCweMapping()

  val endTime = System.currentTimeMillis()
  val scanTime = endTime - startTime

  // 统计结果 - 对标CodeQL的严重程度分级
  val totalIssues = results.values.map(_.length).sum
  val criticalIssues = results.filter { case (ruleId, issues) => 
    severities.getOrElse(ruleId, "LOW") == "CRITICAL" && issues.nonEmpty
  }.values.map(_.length).sum

  val highIssues = results.filter { case (ruleId, issues) => 
    severities.getOrElse(ruleId, "LOW") == "HIGH" && issues.nonEmpty
  }.values.map(_.length).sum

  val mediumIssues = results.filter { case (ruleId, issues) => 
    severities.getOrElse(ruleId, "LOW") == "MEDIUM" && issues.nonEmpty
  }.values.map(_.length).sum

  val lowIssues = results.filter { case (ruleId, issues) => 
    severities.getOrElse(ruleId, "LOW") == "LOW" && issues.nonEmpty
  }.values.map(_.length).sum

  println(s"\n✅ Java安全扫描完成")
  println(s"⏱️  扫描时间: ${scanTime}ms")
  println(s"🔍 发现问题: $totalIssues 个")
  println(s"  - 严重 (9.0+): $criticalIssues")
  println(s"  - 高危 (7.0-8.9): $highIssues") 
  println(s"  - 中危 (4.0-6.9): $mediumIssues")
  println(s"  - 低危 (<4.0): $lowIssues")

  // 详细结果输出 - 对标CodeQL的输出格式
  if (totalIssues > 0) {
    println(s"\n📋 Java漏洞详情:")
    val descriptions = JavaSecurityRules.getRuleDescriptions()
    
    // 按严重程度排序输出
    val sortedResults = results.toSeq.sortBy { case (ruleId, _) =>
      severities.getOrElse(ruleId, "LOW") match {
        case "CRITICAL" => 1
        case "HIGH" => 2  
        case "MEDIUM" => 3
        case "LOW" => 4
        case _ => 5
      }
    }
    
    sortedResults.foreach { case (ruleId, issues) =>
      if (issues.nonEmpty) {
        val severity = severities.getOrElse(ruleId, "MEDIUM")
        val ruleDesc = descriptions.getOrElse(ruleId, ruleId)
        val cwes = cweMapping.getOrElse(ruleId, List()).mkString(", ")
        
        println(s"\n🚨 $ruleDesc (${issues.length}个) - $severity")
        println(s"   📋 CWE: $cwes")
        println(s"   🔍 规则ID: $ruleId")
        issues.zipWithIndex.foreach { case (issue, index) =>
          println(s"   ${index + 1}. $issue")
        }
      }
    }
    
    // 修复建议 - 对标CodeQL的remediation guidance
    println(s"\n💡 修复建议:")
    if (results.getOrElse("java/path-injection", List()).nonEmpty) {
      println(s"  📁 路径遍历: 验证文件路径，使用白名单限制访问")
    }
    if (results.getOrElse("java/sql-injection", List()).nonEmpty) {
      println(s"  🗄️  SQL注入: 使用参数化查询，避免字符串拼接")
    }
    if (results.getOrElse("java/unsafe-deserialization", List()).nonEmpty) {
      println(s"  ⚠️  反序列化: 避免反序列化不受信任的数据，使用白名单")
    }
    if (results.getOrElse("java/server-side-template-injection", List()).nonEmpty) {
      println(s"  🎭 模板注入: 对模板输入进行严格验证和沙箱化")
    }
    if (results.getOrElse("java/xxe", List()).nonEmpty) {
      println(s"  📄 XXE: 禁用XML外部实体解析，使用安全的XML解析器配置")
    }
    if (results.getOrElse("java/spring-boot-exposed-actuators", List()).nonEmpty) {
      println(s"  🌱 Spring Boot Actuator: 限制actuator端点访问，启用认证")
    }
  } else {
    println(s"\n✅ 恭喜! 未发现Java安全漏洞")
  }

  // 扫描摘要 - 对标CodeQL的coverage报告
  val totalCwes = cweMapping.values.flatten.toSet.size
  println(s"\n📈 扫描摘要:")
  println(s"  - 语言: Java")
  println(s"  - 规则数量: ${results.keys.size}")
  println(s"  - 覆盖CWE: $totalCwes 个CWE类别")
  println(s"  - 对标: CodeQL java-security-extended")
  println(s"  - 检测能力: 注入攻击、反序列化、模板注入、XXE、Spring Boot等")
  println(s"  - 基于: CodeQL外部模型 + Joern CPG")

  println(s"\n🎯 与CodeQL对标完成!")
  
  // 生成SARIF报告
  println(s"\n📊 生成SARIF报告...")
  val descriptions = JavaSecurityRules.getRuleDescriptions()
  
  // 确定报告路径（改为 JSONL）
  val finalReportPath = if (reportPath.nonEmpty) {
    reportPath
  } else {
    s"${projectName}-security-scan.jsonl"
  }
  
  // 生成 JSONL 报告
  generateJsonlReport(results, severities, cweMapping, descriptions, finalReportPath)
  
  // 尝试保存，如果失败也要清理文件
  try {
    save
  } catch {
    case e: Exception =>
      println(s"⚠️ 保存CPG时出错: ${e.getMessage}")
  }
  
  // 保留JSONL报告文件路径信息
  val reportFile = new File(if (reportPath.nonEmpty) reportPath else s"${projectName}-security-scan.jsonl")
  val reportPath_final = if (reportFile.exists()) reportFile.getAbsolutePath else ""
  
  // 让Joern完成所有内部清理后，再清理我们的文件
  println(s"\n🧹 等待Joern完成内部清理...")
  
  // 添加清理钩子，在JVM退出前执行
  Runtime.getRuntime.addShutdownHook(new Thread(() => {
    // 延迟清理，确保Joern完成所有操作
    Thread.sleep(1000)
    
    println(s"🧹 执行最终清理...")
    
    // 删除bin文件
    val binFile = new File(binPath)
    if (binFile.exists()) {
      binFile.delete()
      println(s"✅ 已删除: $binPath")
    }
    
    // 删除workspace目录
    // 只删除生成的bin文件，保留源码
    val cleanupBinFile = new File(s"${projectName}.bin")
    if (cleanupBinFile.exists()) {
      cleanupBinFile.delete()
      println(s"✅ 已删除: ${cleanupBinFile.getName}")
    }
    
    // 显示保留的报告
    if (reportPath_final.nonEmpty) {
      println(s"📄 SARIF报告已保留: $reportPath_final")
    }
  }))
}
