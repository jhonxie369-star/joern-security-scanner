import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object ZipSlipRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    val fileSinks = cpg.call.l.filter { call =>
      call.name.matches("writeFile|writeFileSync|createWriteStream|appendFile|appendFileSync") ||
      call.name.matches("mkdir|mkdirSync|mkdirp") ||
      call.name.matches("rename|renameSync|copyFile|copyFileSync") ||
      (call.name.matches("extract|extractTo|extractAll") && 
       (call.code.contains("zip") || call.code.contains("tar") || call.code.contains("gz"))) ||
      call.name.matches("pipe|createReadStream") ||
      call.name.matches("sendFile|download")
    }
    
    val zipSources = cpg.call.l.filter { call =>
      (call.code.contains("zip") || call.code.contains("ZIP")) && 
      call.name.matches("entry|file|path|name|fileName") ||
      (call.code.contains("tar") || call.code.contains("TAR")) && 
      call.name.matches("entry|header|path|name") ||
      call.name.matches("entryName|fileName|relativePath|fullPath") ||
      call.methodFullName.matches(".*\\.(zip|tar|gz|bz2).*")
    }
    
    fileSinks.foreach { sink =>
      zipSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty && !hasZipSlipProtection(sink, cpg)) {
          val sinkFile = sink.file.name.headOption.getOrElse("unknown")
          val sinkLine = sink.lineNumber.getOrElse(0)
          
          val key = s"$sinkFile:$sinkLine:zipslip"
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
            
            results += s"""{"rule":"zipslip","severity":"high","file":"$sinkFile","line":$sinkLine,"message":"Zip Slip路径遍历风险","sink_code":"${DataFlowUtils.escapeJson(sink.code)}","dataflow_path":[$contextJson]}"""
          }
        }
      }
    }
    
    results.toList
  }
  
  def hasZipSlipProtection(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                          cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val code = sink.code.toLowerCase
    val protectionPatterns = List(
      "path.resolve", "path.normalize", "path.join", "path.relative",
      "startswith", "includes", "contains", "../", "..\\",
      "sanitize", "validate", "whitelist", "allowlist",
      "safe-extract", "extract-zip"
    )
    protectionPatterns.exists(code.contains) ||
    hasPathTraversalCheck(sink, cpg)
  }
  
  def hasPathTraversalCheck(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                           cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val code = sink.code
    code.contains("../") || code.contains("..\\") ||
    code.contains("indexOf") || code.contains("startsWith")
  }
  
  def hasPathValidation(sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                       cpg: io.shiftleft.codepropertygraph.Cpg): Boolean = {
    val code = sink.code.toLowerCase
    val validationPatterns = List(
      "path.resolve", "path.normalize", "path.join",
      "startswith", "includes", "../", "..\\",
      "sanitize", "validate"
    )
    validationPatterns.exists(code.contains)
  }
}
