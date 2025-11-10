import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

// 参考CodeQL js/jwt-missing-verification规则
object JwtVulnerabilitiesRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    // 检测JWT库的使用 - 参考CodeQL的JWT相关规则
    val jwtCalls = cpg.call.l.filter { call =>
      // jsonwebtoken库
      (call.name.matches("sign|verify|decode") && 
       (call.methodFullName.contains("jsonwebtoken") || 
        call.code.contains("jwt.") ||
        call.code.contains("jsonwebtoken"))) ||
      // jose库
      (call.name.matches("sign|verify|decrypt") &&
       call.methodFullName.contains("jose")) ||
      // node-jsonwebtoken
      call.code.contains("JWT.") ||
      // 其他JWT库
      call.code.toLowerCase.contains("jwt") && call.name.matches("sign|verify|decode")
    }
    
    jwtCalls.foreach { call =>
      val file = call.file.name.headOption.getOrElse("unknown")
      val line = call.lineNumber.getOrElse(0)
      
      val vulnerabilities = detectJwtVulnerabilities(call)
      
      vulnerabilities.foreach { vuln =>
        val key = s"$file:$line:jwt-${vuln._1}"
        if (!seen.contains(key)) {
          seen += key
          
          val pathJson = s"""{
  "ruleId": "javascript/jwt-vulnerabilities",
  "severity": "${vuln._2}",
  "vulnerability": {"file": "$file", "line": $line, "code": "${escapeJson(call.code)}"},
  "context": [{"order": 1, "file": "$file", "line": $line, "code": "${escapeJson(call.code)}"}]
}"""
          
          results += pathJson
        }
      }
    }
    
    results.toList
  }
  
  def detectJwtVulnerabilities(call: io.shiftleft.codepropertygraph.generated.nodes.Call): List[(String, String)] = {
    val vulnerabilities = scala.collection.mutable.ListBuffer[(String, String)]()
    val code = call.code.toLowerCase
    val args = call.argument.l
    
    // 1. 检测算法设置为none - 参考CodeQL jwt-missing-verification
    if (code.contains("algorithm") && (code.contains("\"none\"") || code.contains("'none'"))) {
      vulnerabilities += (("none-algorithm", "CRITICAL"))
    }
    
    // 2. 检测弱密钥
    args.foreach { arg =>
      val argCode = arg.code.replaceAll("\"", "").replaceAll("'", "")
      if (isWeakJwtSecret(argCode)) {
        vulnerabilities += (("weak-secret", "HIGH"))
      }
    }
    
    // 3. 检测缺少验证 - jwt.decode without verification
    if (call.name == "decode" && !code.contains("verify")) {
      vulnerabilities += (("missing-verification", "HIGH"))
    }
    
    // 4. 检测不安全的算法
    if (code.contains("algorithm") && (code.contains("hs256") || code.contains("rs256"))) {
      // 这里可以添加更复杂的算法安全性检查
    }
    
    vulnerabilities.toList
  }
  
  def isWeakJwtSecret(secret: String): Boolean = {
    if (secret.length < 32) return true
    
    val weakSecrets = List(
      "secret", "key", "password", "123456", "test", "jwt", "token", 
      "your-256-bit-secret", "your-secret-key", "mysecret", "secretkey"
    )
    
    val lowerSecret = secret.toLowerCase
    weakSecrets.exists(weak => lowerSecret.contains(weak)) ||
    secret.matches("^[a-zA-Z0-9]{1,20}$") // 简单的字母数字组合
  }
  
  def escapeJson(str: String): String = {
    str.replace("\\", "\\\\")
       .replace("\"", "\\\"")
       .replace("\n", "\\n")
       .replace("\r", "\\r")
       .replaceAll("\\s+", " ")
       .trim
  }
  
  def getRuleInfo(): Map[String, Any] = Map(
    "id" -> "javascript/jwt-vulnerabilities",
    "name" -> "JWT安全漏洞",
    "severity" -> "HIGH",
    "cwe" -> List("CWE-347", "CWE-326"),
    "description" -> "检测JWT库的安全配置问题，参考CodeQL规则"
  )
}
