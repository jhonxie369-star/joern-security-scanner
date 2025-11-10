import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.semanticcpg.language._

// CWE-502: 不安全反序列化规则 - 对标CodeQL UnsafeDeserialization
object UnsafeDeserializationRule {
  
  // 对标CodeQL的sinkNode(this, "deserialization")
  def sinkNode(cpg: io.shiftleft.codepropertygraph.Cpg, kind: String, safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]) = {
    // 反序列化sink点
    (
      // ObjectInputStream.readObject()
      safeCalls.filter(c => 
        c.methodFullName.contains("ObjectInputStream") && c.name == "readObject"
      ) ++
      
      // XMLDecoder.readObject()
      safeCalls.filter(c =>
        c.methodFullName.contains("XMLDecoder") && c.name == "readObject"
      ) ++
      
      // Kryo反序列化
      safeCalls.filter(c =>
        c.methodFullName.contains("Kryo") && 
        Set("readObject", "readClassAndObject").contains(c.name)
      ) ++
      
      // Jackson反序列化
      safeCalls.filter(c =>
        c.methodFullName.contains("ObjectMapper") && 
        Set("readValue", "readTree").contains(c.name)
      ) ++
      
      // Gson反序列化
      safeCalls.filter(c =>
        c.methodFullName.contains("Gson") && c.name == "fromJson"
      )
    ).l
  }
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg, sources: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode], safeCalls: List[io.shiftleft.codepropertygraph.generated.nodes.Call]): List[String] = {
    implicit val engineContext: EngineContext = EngineContext()
    
    val sinks = sinkNode(cpg, "deserialization", safeCalls)
    val flowPaths = sinks.reachableByFlows(sources).l
    
    val groupedFlows = flowPaths.groupBy(flow => {
      val sink = flow.elements.last
      val loc = sink.location
      (loc.filename, loc.lineNumber.getOrElse(1))
    }).map { case (_, flows) =>
      flows.sortBy(f => f.elements.last.location.lineNumber.getOrElse(1)).head
    }
    
    groupedFlows.map { flow =>
      val sink = flow.elements.last
      val sinkLoc = sink.location
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
        rule = "unsafe-deserialization",
        severity = "high",
        file = sinkLoc.filename,
        line = sinkLoc.lineNumber.getOrElse(1),
        message = "不安全反序列化风险: 用户输入未经验证直接反序列化",
        sinkCode = sink.code,
        dataflowPath = path
      )
    }.toList
  }
}
