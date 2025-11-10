import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-273: 不安全证书信任规则 - 对标CodeQL UnsafeCertTrust
object UnsafeCertTrustRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, sources: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    implicit val engineContext: EngineContext = EngineContext()
    
    val unsafeCertPatterns = (
      // 空的TrustManager实现
      safeCalls.filter(c => 
        c.methodFullName.contains("TrustManager") && c.name == "checkServerTrusted"
      ) ++
      
      // 禁用主机名验证
      safeCalls.filter(c =>
        c.methodFullName.contains("setHostnameVerifier") ||
        c.methodFullName.contains("ALLOW_ALL_HOSTNAME_VERIFIER")
      ) ++
      
      // 接受所有证书
      safeCalls.filter(c =>
        c.code.contains("trustAllCerts") ||
        c.code.contains("TrustAllTrustManager") ||
        c.code.contains("AcceptAllTrustManager")
      ) ++
      
      // SSL上下文不安全配置
      safeCalls.filter(c =>
        c.methodFullName.contains("SSLContext") && 
        c.argument.code.exists(_.contains("null"))
      )
    ).l
    
    unsafeCertPatterns.map { pattern =>
      val location = pattern.location
      
      JsonlHelper.formatFinding(
        rule = "unsafe-cert-trust",
        severity = "high",
        file = location.filename,
        line = location.lineNumber.getOrElse(1),
        message = "不安全的证书信任: 禁用了SSL/TLS证书验证",
        sinkCode = pattern.code,
        dataflowPath = List((location.filename, location.lineNumber.getOrElse(1), pattern.code))
      )
    }.distinct
  }
}
