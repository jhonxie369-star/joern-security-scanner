//> using file cwe/PathTraversalRule.sc
//> using file cwe/FilePathTraversalRule.sc
//> using file cwe/PartialPathTraversalRule.sc
//> using file cwe/PartialPathTraversalFromRemoteRule.sc
//> using file cwe/SqlInjectionRule.sc
//> using file cwe/SqlConcatenatedRule.sc
//> using file cwe/XssRule.sc
//> using file cwe/CommandInjectionRule.sc
//> using file cwe/UnsafeDeserializationRule.sc
//> using file cwe/TemplateInjectionRule.sc
//> using file cwe/XxeRule.sc
//> using file cwe/LdapInjectionRule.sc
//> using file cwe/XpathInjectionRule.sc
//> using file cwe/UnsafeCertTrustRule.sc
//> using file cwe/CleartextStorageRule.sc
//> using file cwe/HardcodedCredentialsRule.sc
//> using file cwe/ZipSlipRule.sc
//> using file cwe/UrlRedirectionRule.sc
//> using file cwe/LogInjectionRule.sc
//> using file cwe/Log4jInjectionRule.sc
//> using file cwe/JndiInjectionRule.sc
//> using file cwe/SsrfInjectionRule.sc
//> using file cwe/SpelInjectionRule.sc
//> using file cwe/XsltInjectionRule.sc
//> using file cwe/SpringBootActuatorRule.sc

import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

// JSONL 格式化辅助函数
object JsonlHelper {
  def escapeJson(str: String): String = {
    str.replace("\\", "\\\\")
       .replace("\"", "\\\"")
       .replace("\n", "\\n")
       .replace("\r", "\\r")
       .replaceAll("\\s+", " ")
       .trim
  }
  
  def formatFinding(
    rule: String,
    severity: String,
    file: String,
    line: Int,
    message: String,
    sinkCode: String,
    dataflowPath: List[(String, Int, String)]
  ): String = {
    val pathJson = dataflowPath.zipWithIndex.map { case ((f, l, c), idx) =>
      s"""{"step":${idx + 1},"file":"$f","line":$l,"code":"${escapeJson(c)}"}"""
    }.mkString(",")
    
    s"""{"rule":"$rule","severity":"$severity","file":"$file","line":$line,"message":"${escapeJson(message)}","sink_code":"${escapeJson(sinkCode)}","dataflow_path":[$pathJson]}"""
  }
}

// Java安全规则协调器 - 对标CodeQL的16个核心规则
object JavaSecurityRules {
  
  // 获取指定kind的CodeQL污点源 - 对标CodeQL的sourceModel
  def getSourcesForKind(cpg: io.shiftleft.codepropertygraph.Cpg, kind: String, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[io.shiftleft.codepropertygraph.generated.nodes.AstNode] = {
    val (_, sources) = JavaModelParser.parseModels(kind)
    
    if (sources.isEmpty) {
      println(s"🔧 ${kind}类型无sources，跳过CPG查询")
      return List.empty
    }
    
    sources.flatMap { source =>
      safeCalls.filter { call =>
        val fullName = call.methodFullName
        fullName.contains(source.packageName) && 
        fullName.contains(source.className) && 
        fullName.contains(source.methodName)
      }.flatMap { call =>
        interpretOutput(call, source.output)
      }
    }.map(_.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.AstNode])
  }
  
  // 对标CodeQL的output解释器
  private def interpretOutput(call: io.shiftleft.codepropertygraph.generated.nodes.Call, output: String): List[io.shiftleft.codepropertygraph.generated.nodes.AstNode] = {
    output match {
      case "ReturnValue" => List(call.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.AstNode])
      case s if s.startsWith("Argument[") => 
        val argIndex = s.replace("Argument[", "").replace("]", "")
        if (argIndex == "this") {
          call.receiver.headOption.map(_.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.AstNode]).toList
        } else {
          try {
            val index = argIndex.toInt
            call.argument.drop(index).headOption.map(_.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.AstNode]).toList
          } catch {
            case _: NumberFormatException => List()
          }
        }
      case _ => List()
    }
  }

  // 获取所有污点源 - 已废弃，改用getSourcesForKind
  @deprecated("使用getSourcesForKind替代", "1.0")
  def getAllSources(cpg: io.shiftleft.codepropertygraph.Cpg) = {
    // 返回空列表，强制使用新的基于kind的方法
    List()
  }
  
  // 扫描Java项目的所有安全问题 - 对标CodeQL security-extended (每个规则使用自己的污点源)
  def scanJavaProject(cpg: io.shiftleft.codepropertygraph.Cpg, projectPath: String, timeConsumingMethods: Set[String]): Map[String, List[String]] = {
    println("🔍 开始逐个规则检测...")
    
    // 统一定义安全的方法调用列表，过滤参数过多的方法
    val safeCalls = cpg.call
      .filter(_.argument.size < 50)
      .l
    println(s"🔧 安全方法调用数量: ${safeCalls.size}")
    
    // 定义统一的过滤器，排除耗时方法
    def isTimeConsumingCall(call: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
      timeConsumingMethods.exists(method => call.methodFullName.contains(method))
    }
    
    // 使用remote作为通用污点源 - 对标CodeQL的RemoteFlowSource
    val remoteSources = getSourcesForKind(cpg, "remote", safeCalls)
    println(s"🔍 通用远程污点源: ${remoteSources.size} 个")
    
    val pathSources = remoteSources // 路径遍历使用远程污点源
    println(s"   📊 路径遍历污点源: ${pathSources.size} 个")
    val pathResults = PathTraversalRule.detect(cpg, pathSources, safeCalls)
    
    val filePathSources = remoteSources // 文件路径遍历使用远程污点源
    println(s"   📊 文件路径遍历污点源: ${filePathSources.size} 个")
    val filePathResults = FilePathTraversalRule.detect(cpg, filePathSources, safeCalls)
    
    // 部分路径遍历检测 (静态检测，不需要污点源)
    println(s"   📊 部分路径遍历检测")
    val partialPathResults = PartialPathTraversalRule.detect(cpg, safeCalls)
    
    // 远程部分路径遍历检测
    val partialPathRemoteSources = remoteSources
    println(s"   📊 远程部分路径遍历污点源: ${partialPathRemoteSources.size} 个")
    val partialPathRemoteResults = PartialPathTraversalFromRemoteRule.detect(cpg, partialPathRemoteSources, safeCalls)
    
    val sqlSources = remoteSources // SQL注入使用远程污点源
    println(s"   📊 SQL注入污点源: ${sqlSources.size} 个")
    val sqlResults = SqlInjectionRule.detect(cpg, sqlSources, safeCalls)
    
    // SQL拼接注入检测 (静态检测，不需要污点源)
    println(s"   📊 SQL拼接注入检测")
    val sqlConcatenatedResults = SqlConcatenatedRule.detect(cpg, safeCalls)
    
    val xssSources = remoteSources // XSS使用远程污点源
    println(s"   📊 XSS污点源: ${xssSources.size} 个")
    val xssResults = XssRule.detect(cpg, xssSources, safeCalls)
    
    val cmdSources = remoteSources // 命令注入使用远程污点源
    println(s"   📊 命令注入污点源: ${cmdSources.size} 个")
    val cmdResults = CommandInjectionRule.detect(cpg, cmdSources, safeCalls)
    
    val deserSources = remoteSources
    println(s"   📊 反序列化污点源: ${deserSources.size} 个")
    val deserResults = UnsafeDeserializationRule.detect(cpg, deserSources, safeCalls)
    
    val tplSources = remoteSources
    println(s"   📊 模板注入污点源: ${tplSources.size} 个")
    val tplResults = TemplateInjectionRule.detect(cpg, tplSources, safeCalls)
    
    val xxeSources = remoteSources
    println(s"   📊 XXE污点源: ${xxeSources.size} 个")
    val xxeResults = XxeRule.detect(cpg, xxeSources, safeCalls)
    
    val ldapSources = remoteSources
    println(s"   📊 LDAP注入污点源: ${ldapSources.size} 个")
    val ldapResults = LdapInjectionRule.detect(cpg, ldapSources, safeCalls)
    
    val xpathSources = remoteSources
    println(s"   📊 XPath注入污点源: ${xpathSources.size} 个")
    val xpathResults = XpathInjectionRule.detect(cpg, xpathSources, safeCalls)
    
    val zipSources = remoteSources
    println(s"   📊 Zip Slip污点源: ${zipSources.size} 个")
    val zipResults = ZipSlipRule.detect(cpg, zipSources, safeCalls)
    
    val urlSources = remoteSources
    println(s"   📊 URL重定向污点源: ${urlSources.size} 个")
    val urlResults = UrlRedirectionRule.detect(cpg, urlSources, safeCalls)
    
    val logSources = remoteSources
    // println(s"   📊 日志注入污点源: ${logSources.size} 个")
    // val logResults = LogInjectionRule.detect(cpg, logSources)
    val logResults = List.empty[String]  // 禁用日志注入检测
    
    val log4jSources = remoteSources
    println(s"   📊 Log4j JNDI注入污点源: ${log4jSources.size} 个")
    val log4jResults = Log4jInjectionRule.detect(cpg, log4jSources, safeCalls)
    
    val jndiSources = remoteSources
    println(s"   📊 JNDI注入污点源: ${jndiSources.size} 个")
    val jndiResults = JndiInjectionRule.detect(cpg, jndiSources, safeCalls)
    
    val ssrfSources = remoteSources
    println(s"   📊 SSRF污点源: ${ssrfSources.size} 个")
    val ssrfResults = SsrfInjectionRule.detect(cpg, ssrfSources, safeCalls)
    
    val spelSources = remoteSources
    println(s"   📊 SpEL注入污点源: ${spelSources.size} 个")
    val spelResults = SpelInjectionRule.detect(cpg, spelSources, safeCalls)
    
    val xsltSources = remoteSources
    println(s"   📊 XSLT注入污点源: ${xsltSources.size} 个")
    val xsltResults = XsltInjectionRule.detect(cpg, xsltSources, safeCalls)
    
    val springSources = remoteSources
    println(s"   📊 Spring Boot Actuator污点源: ${springSources.size} 个")
    val springResults = SpringBootActuatorRule.detect(projectPath)  // 直接传入项目路径
    
    Map(
      "java/path-injection" -> pathResults,
      "java/file-path-injection" -> filePathResults,
      "java/partial-path-traversal" -> partialPathResults,
      "java/partial-path-traversal-from-remote" -> partialPathRemoteResults,
      "java/sql-injection" -> sqlResults,
      "java/concatenated-sql-query" -> sqlConcatenatedResults,
      "java/xss" -> xssResults,
      "java/command-injection" -> cmdResults,
      "java/unsafe-deserialization" -> deserResults,
      "java/server-side-template-injection" -> tplResults,
      "java/xxe" -> xxeResults,
      "java/ldap-injection" -> ldapResults,
      "java/xpath-injection" -> xpathResults,
      "java/zip-slip" -> zipResults,
      "java/url-redirection" -> urlResults,
      "java/log4j-injection" -> log4jResults,
      "java/jndi-injection" -> jndiResults,
      "java/ssrf" -> ssrfResults,
      "java/spel-expression-injection" -> spelResults,
      "java/xslt-injection" -> xsltResults,
      "java/spring-boot-exposed-actuators" -> springResults
    )
  }
  
  // 获取规则描述 - 对标CodeQL的@name注解
  def getRuleDescriptions(): Map[String, String] = {
    Map(
      "java/path-injection" -> "CWE-022 路径遍历",
      "java/file-path-injection" -> "CWE-023 文件路径遍历",
      "java/partial-path-traversal" -> "CWE-023 部分路径遍历",
      "java/partial-path-traversal-from-remote" -> "CWE-023 远程部分路径遍历",
      "java/sql-injection" -> "CWE-089 SQL注入", 
      "java/concatenated-sql-query" -> "CWE-089 SQL拼接注入",
      "java/xss" -> "CWE-079 跨站脚本",
      "java/command-injection" -> "CWE-078 命令注入",
      "java/unsafe-deserialization" -> "CWE-502 不安全反序列化",
      "java/server-side-template-injection" -> "CWE-094 服务端模板注入",
      "java/xxe" -> "CWE-611 XML外部实体注入",
      "java/ldap-injection" -> "CWE-090 LDAP注入",
      "java/xpath-injection" -> "CWE-643 XPath注入",
      "java/zip-slip" -> "CWE-022 Zip Slip攻击",
      "java/url-redirection" -> "CWE-601 开放重定向",
      "java/log-injection" -> "CWE-117 日志注入",
      "java/log4j-injection" -> "CWE-020/CWE-074 Log4j JNDI注入 (CVE-2021-44228)",
      "java/jndi-injection" -> "CWE-074 JNDI注入",
      "java/ssrf" -> "CWE-918 服务端请求伪造",
      "java/spel-expression-injection" -> "CWE-094 SpEL表达式注入",
      "java/xslt-injection" -> "CWE-074 XSLT注入",
      "java/spring-boot-exposed-actuators" -> "CWE-200 Spring Boot Actuator暴露"
    )
  }
  
  // 获取规则严重程度 - 对标CodeQL的@security-severity
  def getRuleSeverities(): Map[String, String] = {
    Map(
      "java/path-injection" -> "HIGH",           // 7.5
      "java/file-path-injection" -> "HIGH",     // 7.5
      "java/partial-path-traversal" -> "CRITICAL", // 9.3
      "java/partial-path-traversal-from-remote" -> "CRITICAL", // 9.3
      "java/sql-injection" -> "CRITICAL",       // 8.8 -> 9.1
      "java/concatenated-sql-query" -> "CRITICAL", // 8.8 -> 9.1
      "java/xss" -> "HIGH",                      // 6.1
      "java/command-injection" -> "CRITICAL",   // 9.3
      "java/unsafe-deserialization" -> "CRITICAL", // 9.8
      "java/server-side-template-injection" -> "CRITICAL", // 9.3
      "java/xxe" -> "CRITICAL",                 // 9.1
      "java/ldap-injection" -> "CRITICAL",      // 8.8 -> 9.1
      "java/xpath-injection" -> "CRITICAL",     // 8.8 -> 9.1
      "java/zip-slip" -> "HIGH",                // 7.5
      "java/url-redirection" -> "MEDIUM",       // 6.1
      "java/log-injection" -> "LOW",            // 5.3
      "java/log4j-injection" -> "CRITICAL",     // 10.0 (CVE-2021-44228)
      "java/jndi-injection" -> "CRITICAL",      // 9.8
      "java/ssrf" -> "CRITICAL",                // 9.1
      "java/spel-expression-injection" -> "CRITICAL", // 9.3
      "java/xslt-injection" -> "CRITICAL",      // 9.8
      "java/spring-boot-exposed-actuators" -> "CRITICAL" // 9.0+
    )
  }
  
  // 获取CWE映射 - 对标CodeQL的external/cwe标签
  def getCweMapping(): Map[String, List[String]] = {
    Map(
      "java/path-injection" -> List("CWE-022", "CWE-036", "CWE-073"),
      "java/file-path-injection" -> List("CWE-023"),
      "java/partial-path-traversal" -> List("CWE-023"),
      "java/partial-path-traversal-from-remote" -> List("CWE-023"),
      "java/sql-injection" -> List("CWE-089", "CWE-564"),
      "java/concatenated-sql-query" -> List("CWE-089", "CWE-564"),
      "java/xss" -> List("CWE-079", "CWE-116"),
      "java/command-injection" -> List("CWE-078", "CWE-088"),
      "java/unsafe-deserialization" -> List("CWE-502"),
      "java/server-side-template-injection" -> List("CWE-094", "CWE-1336"),
      "java/xxe" -> List("CWE-611", "CWE-827"),
      "java/ldap-injection" -> List("CWE-090"),
      "java/xpath-injection" -> List("CWE-643"),
      "java/zip-slip" -> List("CWE-022", "CWE-023"),
      "java/url-redirection" -> List("CWE-601"),
      "java/log-injection" -> List("CWE-117"),
      "java/log4j-injection" -> List("CWE-020", "CWE-074", "CWE-400", "CWE-502"),
      "java/jndi-injection" -> List("CWE-074"),
      "java/ssrf" -> List("CWE-918"),
      "java/spel-expression-injection" -> List("CWE-094"),
      "java/xslt-injection" -> List("CWE-074"),
      "java/spring-boot-exposed-actuators" -> List("CWE-200")
    )
  }
}
