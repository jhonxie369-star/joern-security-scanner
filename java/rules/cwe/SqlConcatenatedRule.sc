import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-089: SQL拼接注入规则 - 对标CodeQL SqlConcatenated (@kind problem)
object SqlConcatenatedRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    
    // 检测SQL查询中的字符串拼接
    val sqlCalls = getSqlCalls(cpg, safeCalls)
    
    sqlCalls.foreach { call =>
      call.argument.foreach { arg =>
        if (isConcatenatedString(arg)) {
          val location = call.location
          
          val jsonResult = JsonlHelper.formatFinding(
            rule = "sql-concatenated",
            severity = "high",
            file = location.filename,
            line = location.lineNumber.getOrElse(1),
            message = "SQL查询使用字符串拼接构建，存在注入风险",
            sinkCode = call.code,
            dataflowPath = List((location.filename, location.lineNumber.getOrElse(1), call.code))
          )
          results += jsonResult
        }
      }
    }
    
    results.toList.distinct
  }
  
  // 获取SQL相关的方法调用
  private def getSqlCalls(cpg: io.shiftleft.codepropertygraph.Cpg, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    safeCalls.filter { call =>
      val methodName = call.methodFullName
      (
        // JDBC相关
        (methodName.contains("Statement") && Set("executeQuery", "executeUpdate", "execute").contains(call.name)) ||
        (methodName.contains("PreparedStatement") && Set("executeQuery", "executeUpdate", "execute").contains(call.name)) ||
        (methodName.contains("Connection") && Set("prepareStatement", "createStatement").contains(call.name)) ||
        
        // JPA相关
        (methodName.contains("EntityManager") && Set("createQuery", "createNativeQuery").contains(call.name)) ||
        (methodName.contains("Query") && Set("setParameter").contains(call.name)) ||
        
        // MyBatis相关
        (methodName.contains("SqlSession") && Set("selectOne", "selectList", "insert", "update", "delete").contains(call.name)) ||
        
        // Hibernate相关
        (methodName.contains("Session") && Set("createQuery", "createSQLQuery").contains(call.name))
      )
    }
  }
  
  // 检测是否为拼接字符串
  private def isConcatenatedString(arg: io.shiftleft.codepropertygraph.generated.nodes.Expression): Boolean = {
    arg match {
      case call: io.shiftleft.codepropertygraph.generated.nodes.Call =>
        // 检测 + 操作符
        call.name == "+" || call.name == "concat" ||
        // 检测StringBuilder/StringBuffer
        (call.methodFullName.contains("StringBuilder") && Set("append", "toString").contains(call.name)) ||
        (call.methodFullName.contains("StringBuffer") && Set("append", "toString").contains(call.name)) ||
        // 检测String.format
        (call.methodFullName.contains("String") && call.name == "format")
      case _ => false
    }
  }
}
