import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

// 参考CodeQL NosqlInjectionCustomizations的Sink定义
object NoSqlInjectionRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    // 借鉴CodeQL NosqlInjectionCustomizations的Sink定义
    val nosqlSinks = cpg.call.l.filter { call =>
      // MongoDB native driver
      (call.name.matches("find|findOne|update|updateOne|updateMany|remove|deleteOne|deleteMany|aggregate|count|distinct") &&
       (call.methodFullName.contains("mongodb") || call.code.contains("db."))) ||
      // Mongoose ODM
      (call.name.matches("find|findOne|findOneAndUpdate|findOneAndDelete|update|remove|aggregate|count|distinct") &&
       call.methodFullName.contains("mongoose")) ||
      // $where operator - 特别危险
      call.code.contains("$where") ||
      // MapReduce operations
      call.name.matches("mapReduce|group") ||
      // Eval in MongoDB context
      (call.name == "eval" && isInMongoContext(call, cpg))
    }
    
    val userSources = getExpressRequestSources(cpg)
    
    nosqlSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasNoSqlSanitization(sink, cpg)) {
          val sinkFile = sink.file.name.headOption.getOrElse("unknown")
          val sinkLine = sink.lineNumber.getOrElse(0)
          
          val key = s"$sinkFile:$sinkLine:nosql-injection"
          if (!seen.contains(key)) {
            seen += key
            
            val pathNodes = DataFlowUtils.buildRealDataFlowPath(source, sink, cpg)
            
            val contextItems = scala.collection.mutable.ListBuffer[(String, Int, String)]()
            contextItems += ((source.file.name.headOption.getOrElse("unknown"), source.lineNumber.getOrElse(0), DataFlowUtils.escapeJson(source.code)))
            
            pathNodes.foreach { node =>
              contextItems += ((node._1, node._2, DataFlowUtils.escapeJson(node._3)))
            }
            
            val contextJson = contextItems.zipWithIndex.map { case ((file, line, code), index) =>
              s"""{"step":${index+1},"file":"$file","line":$line,"code":"$code"}"""
            }.mkString(",")
            
            results += s"""{"rule":"nosql-injection","severity":"critical","file":"$sinkFile","line":$sinkLine,"message":"NoSQL注入风险","sink_code":"${DataFlowUtils.escapeJson(sink.code)}","dataflow_path":[$contextJson]}"""
          }
        }
      }
    }
    
    results.toList
  }
  
  def hasNoSqlSanitization(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                          cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val code = sink.code.toLowerCase
    
    // 借鉴CodeQL NoSqlSanitizer
    val sanitizerPatterns = List(
      "sanitize", "validate", "escape", "objectid",
      "mongoose.types.objectid", "bson.objectid",
      "whitelist", "allowlist", "schema.validate"
    )
    
    sanitizerPatterns.exists(code.contains) ||
    isSecureQueryConstruction(sink)
  }
  
  def isSecureQueryConstruction(sink: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val code = sink.code.toLowerCase
    code.contains("$eq") || code.contains("$ne") || code.contains("$in") ||
    code.contains("objectid") || code.contains("isvalid")
  }
  
  def isInMongoContext(call: io.shiftleft.codepropertygraph.generated.nodes.Call, 
                      cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    call.code.toLowerCase.contains("mongo") ||
    call.code.toLowerCase.contains("collection")
  }
  
  def getExpressRequestSources(cpg: io.shiftleft.codepropertygraph.Cpg): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    // Express请求属性访问
    cpg.call.name("<operator>.fieldAccess").l.filter { call =>
      call.argument.order(1).code.headOption.exists(_.matches("req\\.(query|body|params|headers|cookies)"))
    }
  }
}
