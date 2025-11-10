import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-312: 明文存储敏感信息规则 - 对标CodeQL CleartextStorage
object CleartextStorageRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, sources: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    implicit val engineContext: EngineContext = EngineContext()
    
    // 敏感信息关键词
    val sensitiveKeywords = Set("password", "passwd", "pwd", "secret", "key", "token", "credential", "auth")
    
    val cleartextSinks = (
      // Properties文件存储
      safeCalls.filter(c => 
        c.methodFullName.contains("Properties") && 
        Set("setProperty", "store").contains(c.name) &&
        c.argument.code.exists(arg => sensitiveKeywords.exists(keyword => arg.toLowerCase.contains(keyword)))
      ) ++
      
      // SharedPreferences存储
      safeCalls.filter(c =>
        c.methodFullName.contains("SharedPreferences") && 
        Set("putString", "edit").contains(c.name) &&
        c.argument.code.exists(arg => sensitiveKeywords.exists(keyword => arg.toLowerCase.contains(keyword)))
      ) ++
      
      // 数据库存储
      safeCalls.filter(c =>
        c.methodFullName.contains("ContentValues") && c.name == "put" &&
        c.argument.code.exists(arg => sensitiveKeywords.exists(keyword => arg.toLowerCase.contains(keyword)))
      ) ++
      
      // 文件写入
      safeCalls.filter(c =>
        (c.methodFullName.contains("FileWriter") || c.methodFullName.contains("PrintWriter")) &&
        c.name == "write" &&
        c.argument.code.exists(arg => sensitiveKeywords.exists(keyword => arg.toLowerCase.contains(keyword)))
      )
    ).l
    
    cleartextSinks.map { sink =>
      val location = sink.location
      
      JsonlHelper.formatFinding(
        rule = "cleartext-storage",
        severity = "high",
        file = location.filename,
        line = location.lineNumber.getOrElse(1),
        message = "明文存储敏感信息: 敏感数据未加密存储",
        sinkCode = sink.code,
        dataflowPath = List((location.filename, location.lineNumber.getOrElse(1), sink.code))
      )
    }.distinct
  }
}
