import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object DataFlowUtils {
  
  // 真正的DDG数据流路径追踪
  def buildRealDataFlowPath(source: io.shiftleft.codepropertygraph.generated.nodes.Call, 
                            sink: io.shiftleft.codepropertygraph.generated.nodes.Call,
                            cpg: io.shiftleft.codepropertygraph.Cpg,
                            maxDepth: Int = 5): List[(String, Int, String)] = {
    val path = scala.collection.mutable.ListBuffer[(String, Int, String)]()
    val ddgNodes = sink.reachableBy(List(source)).l
    
    ddgNodes.foreach { node =>
      if (node != source && node != sink) {
        val file = node.file.name.headOption.getOrElse("unknown")
        val line = node.lineNumber.getOrElse(0)
        val code = node.code
        
        if (line > 0 && code.nonEmpty) {
          path += ((file, line, code))
        }
      }
    }
    
    // 保持原始顺序（数据流递进顺序），只限制深度
    path.toList.take(maxDepth)
  }
  
  def escapeJson(s: String): String = {
    s.replace("\\", "\\\\")
     .replace("\"", "\\\"")
     .replace("\n", "\\n")
     .replace("\r", "\\r")
     .replace("\t", "\\t")
  }
}
