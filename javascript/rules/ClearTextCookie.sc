import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

// 借鉴CodeQL ClearTextCookieCustomizations
object ClearTextCookieRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    // 借鉴CodeQL的Cookie设置检测
    val cookieSinks = cpg.call.l.filter { call =>
      // Express.js cookie methods
      call.name.matches("cookie|setCookie") ||
      // HTTP response headers
      (call.name.matches("setHeader|writeHead") && 
       call.argument.code.exists(_.toLowerCase.contains("set-cookie"))) ||
      // Cookie libraries
      call.methodFullName.contains("cookie") ||
      // Direct header manipulation
      call.code.toLowerCase.contains("set-cookie")
    }
    
    cookieSinks.foreach { sink =>
      if (!hasSecureCookieConfiguration(sink)) {
        val sinkFile = sink.file.name.headOption.getOrElse("unknown")
        val sinkLine = sink.lineNumber.getOrElse(0)
        
        val key = s"$sinkFile:$sinkLine:clear-text-cookie"
        if (!seen.contains(key)) {
          seen += key
          
          val pathJson = s"""{"rule":"clear-text-cookie","severity":"medium","file":"$sinkFile","line":$sinkLine,"message":"Missing secure cookie flags: ${getCookieSecurityIssue(sink)}","sink_code":"${escapeJson(sink.code)}","dataflow_path":[{"step":1,"file":"$sinkFile","line":$sinkLine,"code":"${escapeJson(sink.code)}"}]}"""
          
          results += pathJson
        }
      }
    }
    
    results.toList
  }
  
  def hasSecureCookieConfiguration(sink: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val code = sink.code.toLowerCase
    val args = sink.argument.l
    
    // 检查secure标志
    val hasSecure = code.contains("secure") && 
                   (code.contains("true") || code.contains(": true"))
    
    // 检查httpOnly标志
    val hasHttpOnly = code.contains("httponly") && 
                     (code.contains("true") || code.contains(": true"))
    
    // 检查SameSite属性
    val hasSameSite = code.contains("samesite") && 
                     (code.contains("strict") || code.contains("lax"))
    
    // 至少需要secure标志
    hasSecure
  }
  
  def getCookieSecurityIssue(sink: io.shiftleft.codepropertygraph.generated.nodes.Call): String = {
    val code = sink.code.toLowerCase
    val issues = scala.collection.mutable.ListBuffer[String]()
    
    if (!code.contains("secure")) {
      issues += "Missing Secure flag"
    }
    
    if (!code.contains("httponly")) {
      issues += "Missing HttpOnly flag"
    }
    
    if (!code.contains("samesite")) {
      issues += "Missing SameSite attribute"
    }
    
    if (issues.isEmpty) "Insecure cookie configuration" else issues.mkString(", ")
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
    "id" -> "javascript/clear-text-cookie",
    "name" -> "不安全的Cookie配置",
    "severity" -> "MEDIUM",
    "cwe" -> List("CWE-614"),
    "description" -> "检测缺少安全标志的Cookie设置，参考CodeQL规则"
  )
}
