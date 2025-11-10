import java.io.File
import scala.io.Source
import scala.util.Try

// CWE-200: Spring Boot Actuator暴露规则 - 直接检测配置文件
object SpringBootActuatorRule {
  
  def detect(projectPath: String): List[String] = {
    checkConfigFiles(projectPath)
  }
  
  // 递归查找配置文件
  private def findConfigFiles(projectPath: String): List[File] = {
    def searchFiles(dir: File): List[File] = {
      if (dir.exists() && dir.isDirectory()) {
        val files = dir.listFiles().toList
        val configFiles = files.filter(f => 
          f.isFile() && (f.getName.endsWith(".yml") || f.getName.endsWith(".yaml") || f.getName.endsWith(".properties"))
        )
        val subDirFiles = files.filter(_.isDirectory()).flatMap(searchFiles)
        configFiles ++ subDirFiles
      } else List.empty
    }
    
    searchFiles(new File(projectPath))
  }
  
  // 检查配置文件内容
  private def checkConfigFiles(projectPath: String): List[String] = {
    val configFiles = findConfigFiles(projectPath)
    
    configFiles.flatMap { file =>
      Try {
        val content = Source.fromFile(file).mkString
        val issues = scala.collection.mutable.ListBuffer[String]()
        
        // 检测暴露所有端点 - 支持多种格式
        if (content.contains("include: '*'") ||
            content.contains("include: \"*\"") ||
            content.contains("include=*") ||
            content.contains("include: *")) {
          val jsonResult = JsonlHelper.formatFinding(
            rule = "spring-boot-actuator",
            severity = "medium",
            file = file.getPath,
            line = 1,
            message = "Spring Boot Actuator暴露所有端点",
            sinkCode = "management.endpoints.web.exposure.include=*",
            dataflowPath = List((file.getPath, 1, "management.endpoints.web.exposure.include=*"))
          )
          issues += jsonResult
        }
        
        // 检测安全禁用
        if (content.contains("management.security.enabled: false") ||
            content.contains("management.security.enabled=false")) {
          val jsonResult = JsonlHelper.formatFinding(
            rule = "spring-boot-actuator",
            severity = "high",
            file = file.getPath,
            line = 1,
            message = "Spring Boot Actuator安全禁用",
            sinkCode = "management.security.enabled=false",
            dataflowPath = List((file.getPath, 1, "management.security.enabled=false"))
          )
          issues += jsonResult
        }
        
        // 检测敏感端点启用
        if (content.contains("management.endpoint.heapdump.enabled: true") ||
            content.contains("management.endpoint.heapdump.enabled=true")) {
          val jsonResult = JsonlHelper.formatFinding(
            rule = "spring-boot-actuator",
            severity = "medium",
            file = file.getPath,
            line = 1,
            message = "Spring Boot Heapdump端点启用",
            sinkCode = "management.endpoint.heapdump.enabled=true",
            dataflowPath = List((file.getPath, 1, "management.endpoint.heapdump.enabled=true"))
          )
          issues += jsonResult
        }
        
        issues.toList
      }.getOrElse(List.empty)
    }
  }
}
