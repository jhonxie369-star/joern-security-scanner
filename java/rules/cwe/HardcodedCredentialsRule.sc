import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-798: 硬编码凭据规则 - 对标CodeQL HardcodedCredentials
object HardcodedCredentialsRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, sources: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    implicit val engineContext: EngineContext = EngineContext()
    
    val credentialPatterns = (
      // 硬编码密码字面量
      cpg.literal.filter(l => 
        l.code.matches("\".*[pP]assword.*\"") ||
        l.code.matches("\".*[sS]ecret.*\"") ||
        l.code.matches("\".*[kK]ey.*\"") ||
        l.code.matches("\".*[tT]oken.*\"")
      ) ++
      
      // 变量赋值中的硬编码凭据
      cpg.assignment.filter(a =>
        a.target.code.toLowerCase.matches(".*(password|passwd|pwd|secret|key|token|credential).*") &&
        a.source.isLiteral
      ).map(_.source) ++
      
      // 方法调用中的硬编码凭据
      safeCalls.filter(c =>
        Set("setPassword", "setSecret", "setKey", "authenticate", "login").exists(method =>
          c.name.toLowerCase.contains(method.toLowerCase)
        ) &&
        c.argument.isLiteral.nonEmpty
      ).flatMap(_.argument.isLiteral)
    ).l
    
    credentialPatterns.map { pattern =>
      val location = pattern.location
      
      JsonlHelper.formatFinding(
        rule = "hardcoded-credentials",
        severity = "high",
        file = location.filename,
        line = location.lineNumber.getOrElse(1),
        message = "硬编码凭证: 代码中包含硬编码的密码或密钥",
        sinkCode = pattern.code,
        dataflowPath = List((location.filename, location.lineNumber.getOrElse(1), pattern.code))
      )
    }.distinct
  }
}
