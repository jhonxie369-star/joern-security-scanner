import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-22: Zip Slip规则 - 移除复杂防护检测
object ZipSlipRule {
  
  def sinkNode(cpg: io.shiftleft.codepropertygraph.Cpg, kind: String, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    (
      // FileOutputStream - 写文件
      safeCalls.filter(c =>
        c.methodFullName.contains("FileOutputStream") && c.name == "<init>"
      ) ++

      // FileInputStream - 读文件
      safeCalls.filter(c =>
        c.methodFullName.contains("FileInputStream") && c.name == "<init>"
      ) ++

      // Files.copy - 复制文件
      safeCalls.filter(c =>
        c.methodFullName.contains("Files") && c.name == "copy"
      ) ++

      // Files.write - 写文件
      safeCalls.filter(c =>
        c.methodFullName.contains("Files") && c.name == "write"
      ) ++

      // File.createNewFile - 创建文件
      safeCalls.filter(c =>
        c.methodFullName.contains("File") && c.name == "createNewFile"
      ) ++

      // File.mkdir/mkdirs - 创建目录
      safeCalls.filter(c =>
        c.methodFullName.contains("File") && (c.name == "mkdir" || c.name == "mkdirs")
      ) ++

      // MultipartFile.transferTo - 上传文件
      safeCalls.filter(c =>
        c.methodFullName.contains("MultipartFile") && c.name == "transferTo"
      )
    ).l
  }
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, sources: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    implicit val engineContext: EngineContext = EngineContext()
    
    val sinks = sinkNode(cpg, "zip-slip", safeCalls)
    val flowPaths = sinks.reachableByFlows(sources).l
    
    // 按sink（漏洞点）分组去重
    val groupedFlows = flowPaths.groupBy(flow => {
      val sink = flow.elements.last
      val loc = sink.location
      (loc.filename, loc.lineNumber.getOrElse(1))
    }).map { case (_, flows) => flows.head }
    
    groupedFlows.map { flow =>
      val sink = flow.elements.last
      val sinkLoc = sink.location
      
      // 获取数据流路径：显示source、中间步骤、sink
      val allElements = flow.elements.toList
      val pathElements = if (allElements.length <= 5) {
        allElements
      } else {
        // 显示：第1步 + 第2步 + 中间1步 + 倒数第2步 + 最后1步
        val mid = allElements(allElements.length / 2)
        List(allElements(0), allElements(1), mid, allElements(allElements.length - 2), allElements.last)
      }
      val path = pathElements.map { node =>
        val loc = node.location
        (loc.filename, loc.lineNumber.getOrElse(1), node.code)
      }
      
      JsonlHelper.formatFinding(
        rule = "zip-slip",
        severity = "high",
        file = sinkLoc.filename,
        line = sinkLoc.lineNumber.getOrElse(1),
        message = "Zip Slip风险: ZIP文件解压路径未经验证",
        sinkCode = sink.code,
        dataflowPath = path
      )
    }.toList
  }
}
