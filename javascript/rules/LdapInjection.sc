import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.joerncli.console.Joern.context

object LdapInjectionRule {
  
  def detect(cpg: io.shiftleft.codepropertygraph.Cpg): List[String] = {
    val results = scala.collection.mutable.ListBuffer[String]()
    val seen = scala.collection.mutable.Set[String]()
    
    val ldapSinks = cpg.call.name("search|bind|authenticate").l.filter { call =>
      call.methodFullName.exists(_.toLowerCase.contains("ldap")) ||
      call.code.toLowerCase.contains("ldap")
    }
    
    val userSources = cpg.call.l.filter { call =>
      call.code.contains("req.") && (call.code.contains("body") || call.code.contains("query") || call.code.contains("params"))
    }
    
    ldapSinks.foreach { sink =>
      userSources.foreach { source =>
        val reachablePaths = sink.reachableBy(List(source)).l
        
        if (reachablePaths.nonEmpty) {
          val sinkFile = sink.file.name.headOption.getOrElse("unknown")
          val sinkLine = sink.lineNumber.getOrElse(0)
          
          val key = s"$sinkFile:$sinkLine:ldap-injection"
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
            
            results += s"""{"rule":"ldap-injection","severity":"high","file":"$sinkFile","line":$sinkLine,"message":"LDAP注入风险","sink_code":"${DataFlowUtils.escapeJson(sink.code)}","dataflow_path":[$contextJson]}"""
          }
        }
      }
    }
          }
        }
      }
    }
    
    results.toList
  }
}
