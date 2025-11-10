import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

// 参考CodeQL js/incomplete-url-substring-sanitization规则
object IncompleteUrlSubstringSanitizationRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    // URL处理相关的调用
    val urlProcessing = cpg.call.l.filter { call =>
      // 字符串替换操作
      call.name.matches("replace|replaceAll") ||
      // URL验证
      call.name.matches("startsWith|endsWith|includes|indexOf") ||
      // 正则匹配
      call.name.matches("match|test|search")
    }
    
    urlProcessing.foreach { call =>
      val args = call.argument.l
      
      // 检查是否存在不完整的URL清理
      args.foreach { arg =>
        val argCode = arg.code.toLowerCase
        
        if (hasIncompleteUrlSanitization(argCode)) {
          val file = call.file.name.headOption.getOrElse("unknown")
          val line = call.lineNumber.getOrElse(0)
          
          val key = s"$file:$line:incomplete-url-sanitization"
          if (!seen.contains(key)) {
            seen += key
            
            val pathJson = s"""{
  "ruleId": "javascript/incomplete-url-substring-sanitization",
  "severity": "MEDIUM",
  "vulnerability": {"file": "$file", "line": $line, "code": "${escapeJson(call.code)}"},
  "context": [{"order": 1, "file": "$file", "line": $line, "code": "${escapeJson(call.code)}"}],
  "sanitizationPattern": "${escapeJson(argCode)}"
}"""
            
            results += pathJson
          }
        }
      }
    }
    
    results.toList
  }
  
  def hasIncompleteUrlSanitization(argCode: String): Boolean = {
    // 检测不完整的URL清理模式
    val incompletePatterns = List(
      // 简单的javascript:替换，可以被绕过
      ("javascript:", !argCode.contains("javascript:")),
      // 简单的http://替换
      ("http://", argCode.contains("replace") && argCode.contains("http://") && !argCode.contains("https://")),
      // 不完整的协议检查
      ("://", argCode.contains("://") && !argCode.contains("^https?://")),
      // 简单的域名检查
      (".com", argCode.contains(".com") && !argCode.contains("whitelist")),
      // 不完整的路径检查
      ("../", argCode.contains("../") && !argCode.contains("normalize"))
    )
    
    incompletePatterns.exists { case (pattern, condition) =>
      argCode.contains(pattern) && condition
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
  
  def getRuleInfo(): Map[String, Any] = Map(
    "id" -> "javascript/incomplete-url-substring-sanitization",
    "name" -> "不完整的URL子字符串清理",
    "severity" -> "MEDIUM",
    "cwe" -> List("CWE-20"),
    "description" -> "检测不完整的URL清理可能导致绕过，参考CodeQL规则"
  )
}
