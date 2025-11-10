// JavaScript安全规则定义
// 基于CodeQL JavaScript安全规则，适配Joern CPG

object JavaScriptSecurityRules {
  
  // 规则描述映射
  def getRuleDescriptions(): Map[String, String] = Map(
    "javascript/sql-injection" -> "SQL注入漏洞",
    "javascript/xss" -> "跨站脚本攻击(XSS)",
    "javascript/path-injection" -> "路径遍历漏洞", 
    "javascript/command-injection" -> "命令注入漏洞",
    "javascript/unsafe-deserialization" -> "不安全反序列化",
    "javascript/prototype-pollution" -> "原型污染漏洞",
    "javascript/regex-injection" -> "正则表达式注入",
    "javascript/server-side-template-injection" -> "服务端模板注入",
    "javascript/xxe" -> "XML外部实体注入",
    "javascript/ldap-injection" -> "LDAP注入漏洞",
    "javascript/nosql-injection" -> "NoSQL注入漏洞",
    "javascript/code-injection" -> "代码注入漏洞",
    "javascript/open-redirect" -> "开放重定向漏洞",
    "javascript/ssrf" -> "服务端请求伪造",
    "javascript/insecure-randomness" -> "不安全的随机数生成",
    "javascript/weak-cryptography" -> "弱加密算法"
  )
  
  // 规则严重程度映射
  def getRuleSeverities(): Map[String, String] = Map(
    "javascript/sql-injection" -> "CRITICAL",
    "javascript/xss" -> "HIGH", 
    "javascript/path-injection" -> "HIGH",
    "javascript/command-injection" -> "CRITICAL",
    "javascript/unsafe-deserialization" -> "CRITICAL",
    "javascript/prototype-pollution" -> "HIGH",
    "javascript/regex-injection" -> "MEDIUM",
    "javascript/server-side-template-injection" -> "HIGH",
    "javascript/xxe" -> "HIGH",
    "javascript/ldap-injection" -> "HIGH",
    "javascript/nosql-injection" -> "HIGH", 
    "javascript/code-injection" -> "CRITICAL",
    "javascript/open-redirect" -> "MEDIUM",
    "javascript/ssrf" -> "HIGH",
    "javascript/insecure-randomness" -> "MEDIUM",
    "javascript/weak-cryptography" -> "MEDIUM"
  )
  
  // CWE映射
  def getCweMapping(): Map[String, List[String]] = Map(
    "javascript/sql-injection" -> List("CWE-89"),
    "javascript/xss" -> List("CWE-79"),
    "javascript/path-injection" -> List("CWE-22"),
    "javascript/command-injection" -> List("CWE-78"),
    "javascript/unsafe-deserialization" -> List("CWE-502"),
    "javascript/prototype-pollution" -> List("CWE-1321"),
    "javascript/regex-injection" -> List("CWE-1333"),
    "javascript/server-side-template-injection" -> List("CWE-94"),
    "javascript/xxe" -> List("CWE-611"),
    "javascript/ldap-injection" -> List("CWE-90"),
    "javascript/nosql-injection" -> List("CWE-943"),
    "javascript/code-injection" -> List("CWE-94"),
    "javascript/open-redirect" -> List("CWE-601"),
    "javascript/ssrf" -> List("CWE-918"),
    "javascript/insecure-randomness" -> List("CWE-330"),
    "javascript/weak-cryptography" -> List("CWE-327")
  )
}
