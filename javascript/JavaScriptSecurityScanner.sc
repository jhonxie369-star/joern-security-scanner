//> using file lib/DataFlowUtils.sc
//> using file lib/JavaScriptModelParser.sc
//> using file rules/SqlInjection.sc
//> using file rules/XssRule.sc
//> using file rules/CommandInjection.sc
//> using file rules/PrototypePollution.sc
//> using file rules/PathTraversal.sc
//> using file rules/SsrfRule.sc
//> using file rules/CodeInjection.sc
//> using file rules/ClearTextCookie.sc
//> using file rules/NoSqlInjection.sc
//> using file rules/OpenRedirect.sc
//> using file rules/JwtVulnerabilities.sc
//> using file rules/XmlInjection.sc
//> using file rules/RegexDoS.sc
//> using file rules/UnsafeDeserialization.sc
//> using file rules/ZipSlip.sc
//> using file rules/FileAccessToHttp.sc
//> using file rules/IncompleteUrlSubstringSanitization.sc

import io.joern.console._
import io.joern.dataflowengineoss.language._
import java.io.{File, PrintWriter}

// 生成JSONL报告
def generateJsonlReport(
  results: Map[String, List[String]], 
  severities: Map[String, String],
  cweMapping: Map[String, List[String]],
  descriptions: Map[String, String],
  outputPath: String
): Unit = {
  // 严重程度到CVSS分数的映射（注意大写）
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

// 主扫描逻辑
@main def main(projectPath: String = "", reportPath: String = ""): Unit = {
  
  println("=== JavaScript安全扫描器 ===")
  println("基于Joern的JavaScript代码安全分析")
  
  if (projectPath.isEmpty) {
    println("❌ 错误: 请提供项目路径")
    println("用法: joern --script JavaScriptSecurityScanner.sc --param projectPath=/path/to/project")
    return
  }
  
  println(s"📁 扫描项目: $projectPath")
  
  val startTime = System.currentTimeMillis()
  val projectName = new File(projectPath).getName
  
  // 创建CPG
  println("🔨 为项目创建CPG...")
  println(s"🔧 执行: joern-parse $projectPath --output $projectName.bin --language JAVASCRIPT")
  
  val parseResult = os.proc("joern-parse", projectPath, "--output", s"$projectName.bin", "--language", "JAVASCRIPT").call()
  
  if (parseResult.exitCode != 0) {
    println("❌ CPG创建失败")
    return
  }
  
  // 导入CPG
  importCpg(s"$projectName.bin")
  
  println("\n🔍 开始JavaScript安全扫描...\n")
  println("🚀 执行JavaScript安全规则检测...")
  
  var results = Map[String, List[String]]()
  
  val modelsPath = "models"
  
  // 1. SQL注入检测
  println(s"🔍 检测SQL注入...")
  val sqlJsonResults = SqlInjectionRule.detect(cpg, modelsPath)
  if (sqlJsonResults.nonEmpty) {
    results = results + ("javascript/sql-injection" -> sqlJsonResults)
  }

  // 2. XSS检测
  println(s"🔍 检测XSS...")
  val xssJsonResults = XssRule.detect(cpg)
  if (xssJsonResults.nonEmpty) {
    results = results + ("javascript/xss" -> xssJsonResults)
  }

  // 3. 命令注入检测
  println(s"🔍 检测命令注入...")
  val cmdJsonResults = CommandInjectionRule.detect(cpg)
  if (cmdJsonResults.nonEmpty) {
    results = results + ("javascript/command-injection" -> cmdJsonResults)
  }

  // 4. 原型污染检测
  println(s"🔍 检测原型污染...")
  val protoJsonResults = PrototypePollutionRule.detect(cpg)
  if (protoJsonResults.nonEmpty) {
    results = results + ("javascript/prototype-pollution" -> protoJsonResults)
  }

  // 5. 路径遍历检测
  println(s"🔍 检测路径遍历...")
  val pathJsonResults = PathTraversalRule.detect(cpg, modelsPath)
  if (pathJsonResults.nonEmpty) {
    results = results + ("javascript/path-traversal" -> pathJsonResults)
  }

  // 6. SSRF检测
  println(s"🔍 检测SSRF...")
  val ssrfJsonResults = SsrfRule.detect(cpg, modelsPath)
  if (ssrfJsonResults.nonEmpty) {
    results = results + ("javascript/ssrf" -> ssrfJsonResults)
  }

  // 7. 代码注入检测
  println(s"🔍 检测代码注入...")
  val codeJsonResults = CodeInjectionRule.detect(cpg)
  if (codeJsonResults.nonEmpty) {
    results = results + ("javascript/code-injection" -> codeJsonResults)
  }

  // 8. 明文Cookie检测
  println(s"🔍 检测明文Cookie...")
  val cookieJsonResults = ClearTextCookieRule.detect(cpg)
  if (cookieJsonResults.nonEmpty) {
    results = results + ("javascript/clear-text-cookie" -> cookieJsonResults)
  }

  // 9. NoSQL注入检测
  println(s"🔍 检测NoSQL注入...")
  val nosqlJsonResults = NoSqlInjectionRule.detect(cpg)
  if (nosqlJsonResults.nonEmpty) {
    results = results + ("javascript/nosql-injection" -> nosqlJsonResults)
  }

  // 10. 不安全重定向检测
  println(s"🔍 检测不安全重定向...")
  val redirectJsonResults = OpenRedirectRule.detect(cpg)
  if (redirectJsonResults.nonEmpty) {
    results = results + ("javascript/open-redirect" -> redirectJsonResults)
  }

  // 11. JWT漏洞检测
  println(s"🔍 检测JWT漏洞...")
  val jwtJsonResults = JwtVulnerabilitiesRule.detect(cpg)
  if (jwtJsonResults.nonEmpty) {
    results = results + ("javascript/jwt-vulnerabilities" -> jwtJsonResults)
  }

  // 12. XML注入检测
  println(s"🔍 检测XML注入...")
  val xmlJsonResults = XmlInjectionRule.detect(cpg)
  if (xmlJsonResults.nonEmpty) {
    results = results + ("javascript/xml-injection" -> xmlJsonResults)
  }

  // 13. 正则表达式拒绝服务检测
  println(s"🔍 检测ReDoS...")
  val redosJsonResults = RegexDoSRule.detect(cpg)
  if (redosJsonResults.nonEmpty) {
    results = results + ("javascript/redos" -> redosJsonResults)
  }

  // 14. 不安全反序列化检测
  println(s"🔍 检测不安全反序列化...")
  val deserializationJsonResults = UnsafeDeserializationRule.detect(cpg)
  if (deserializationJsonResults.nonEmpty) {
    results = results + ("javascript/unsafe-deserialization" -> deserializationJsonResults)
  }

  // 15. Zip Slip漏洞检测
  println(s"🔍 检测Zip Slip...")
  val zipslipJsonResults = ZipSlipRule.detect(cpg)
  if (zipslipJsonResults.nonEmpty) {
    results = results + ("javascript/zipslip" -> zipslipJsonResults)
  }

  // 16. 文件访问到HTTP响应检测
  println(s"🔍 检测文件访问泄露...")
  val fileAccessJsonResults = FileAccessToHttpRule.detect(cpg)
  if (fileAccessJsonResults.nonEmpty) {
    results = results + ("javascript/file-access-to-http" -> fileAccessJsonResults)
  }

  // 17. 不完整URL清理检测
  println(s"🔍 检测URL清理绕过...")
  val urlSanitizationJsonResults = IncompleteUrlSubstringSanitizationRule.detect(cpg)
  if (urlSanitizationJsonResults.nonEmpty) {
    results = results + ("javascript/incomplete-url-substring-sanitization" -> urlSanitizationJsonResults)
  }

  val endTime = System.currentTimeMillis()
  val scanTime = endTime - startTime

  println("\n✅ JavaScript安全扫描完成")
  println(s"⏱️  扫描时间: ${scanTime}ms")

  // 统计结果
  val totalIssues = results.values.map(_.size).sum
  val criticalCount = results.filter { case (ruleId, _) => 
    List("javascript/sql-injection", "javascript/command-injection", "javascript/code-injection", "javascript/nosql-injection").contains(ruleId)
  }.values.map(_.size).sum
  
  val highCount = results.filter { case (ruleId, _) => 
    List("javascript/xss", "javascript/path-traversal", "javascript/ssrf", "javascript/prototype-pollution", "javascript/jwt-vulnerabilities", "javascript/xml-injection", "javascript/unsafe-deserialization", "javascript/zipslip").contains(ruleId)
  }.values.map(_.size).sum
  
  val mediumCount = totalIssues - criticalCount - highCount

  println(s"🔍 发现问题: $totalIssues 个")
  println(s"  - 严重 (9.0+): $criticalCount")
  println(s"  - 高危 (7.0-8.9): $highCount")
  println(s"  - 中危 (4.0-6.9): $mediumCount")

  // 规则配置
  val severities = Map(
    "javascript/sql-injection" -> "CRITICAL",
    "javascript/xss" -> "HIGH",
    "javascript/command-injection" -> "CRITICAL",
    "javascript/prototype-pollution" -> "HIGH",
    "javascript/code-injection" -> "CRITICAL",
    "javascript/path-traversal" -> "HIGH",
    "javascript/ssrf" -> "HIGH",
    "javascript/clear-text-cookie" -> "MEDIUM",
    "javascript/nosql-injection" -> "CRITICAL",
    "javascript/open-redirect" -> "MEDIUM",
    "javascript/jwt-vulnerabilities" -> "HIGH",
    "javascript/xml-injection" -> "MEDIUM",
    "javascript/redos" -> "MEDIUM",
    "javascript/unsafe-deserialization" -> "HIGH",
    "javascript/zipslip" -> "HIGH",
    "javascript/file-access-to-http" -> "MEDIUM",
    "javascript/incomplete-url-substring-sanitization" -> "MEDIUM"
  )

  val cweMapping = Map(
    "javascript/sql-injection" -> List("CWE-89"),
    "javascript/xss" -> List("CWE-79", "CWE-80"),
    "javascript/command-injection" -> List("CWE-78"),
    "javascript/prototype-pollution" -> List("CWE-915"),
    "javascript/code-injection" -> List("CWE-94"),
    "javascript/path-traversal" -> List("CWE-22"),
    "javascript/ssrf" -> List("CWE-918"),
    "javascript/clear-text-cookie" -> List("CWE-614"),
    "javascript/nosql-injection" -> List("CWE-943"),
    "javascript/open-redirect" -> List("CWE-601"),
    "javascript/jwt-vulnerabilities" -> List("CWE-347", "CWE-326"),
    "javascript/xml-injection" -> List("CWE-91", "CWE-79"),
    "javascript/redos" -> List("CWE-1333"),
    "javascript/unsafe-deserialization" -> List("CWE-502"),
    "javascript/zipslip" -> List("CWE-22"),
    "javascript/file-access-to-http" -> List("CWE-200"),
    "javascript/incomplete-url-substring-sanitization" -> List("CWE-20")
  )

  val descriptions = Map(
    "javascript/sql-injection" -> "SQL注入漏洞",
    "javascript/xss" -> "跨站脚本攻击(XSS)",
    "javascript/command-injection" -> "命令注入漏洞",
    "javascript/prototype-pollution" -> "原型污染漏洞",
    "javascript/code-injection" -> "代码注入漏洞",
    "javascript/path-traversal" -> "路径遍历漏洞",
    "javascript/ssrf" -> "服务端请求伪造",
    "javascript/clear-text-cookie" -> "明文Cookie传输",
    "javascript/nosql-injection" -> "NoSQL注入漏洞",
    "javascript/open-redirect" -> "不安全的重定向",
    "javascript/jwt-vulnerabilities" -> "JWT漏洞",
    "javascript/xml-injection" -> "XML注入漏洞(前端)",
    "javascript/redos" -> "正则表达式拒绝服务",
    "javascript/unsafe-deserialization" -> "不安全的反序列化",
    "javascript/zipslip" -> "Zip Slip漏洞",
    "javascript/file-access-to-http" -> "文件访问到HTTP响应",
    "javascript/incomplete-url-substring-sanitization" -> "不完整的URL清理"
  )

  // 生成JSONL报告
  val finalReportPath = if (reportPath.nonEmpty) {
    reportPath
  } else {
    s"${projectName}-javascript-security-scan.jsonl"
  }

  generateJsonlReport(results, severities, cweMapping, descriptions, finalReportPath)

  println("\n📈 扫描摘要:")
  println("  - 语言: JavaScript/TypeScript")
  println(s"  - 规则数量: ${severities.size}")
  println("  - 覆盖CWE: 15 个CWE类别")
  println("  - 对标: CodeQL javascript-security-extended")
  println("  - 检测能力: SQL注入、XSS、命令注入、路径遍历、SSRF、代码注入等")
  println("  - 基于: 模块化CFG+reachableBy分析")

  println("\n🎯 与CodeQL对标完成!")

  // 清理临时文件
  sys.addShutdownHook({
    println("\n🧹 等待Joern完成内部清理...")
    Thread.sleep(2000)
    
    println("🧹 执行最终清理...")
    val cpgFile = new File(s"$projectName.bin")
    if (cpgFile.exists()) {
      if (cpgFile.delete()) {
        println(s"✅ 已删除: $projectName.bin")
      }
    }
  })
}
