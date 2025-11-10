#!/bin/bash

# Java安全扫描器启动脚本
# 使用方法: ./scan-java.sh [项目路径]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_SCRIPT="$SCRIPT_DIR/java/JavaSecurityScanner.sc"

# 检查参数
if [ $# -eq 0 ]; then
    echo "🔍 Java安全扫描器"
    echo ""
    echo "使用方法:"
    echo "  $0 <项目路径>"
    echo ""
    echo "示例:"
    echo "  $0 /path/to/your/java/project"
    echo "  $0 /tmp/vulnerable-project"
    echo ""
    echo "说明:"
    echo "  - 支持Maven、Gradle、普通Java项目"
    echo "  - 基于CodeQL模型，16个安全规则"
    echo "  - 覆盖OWASP Top 10和CWE常见漏洞"
    exit 1
fi

PROJECT_PATH="$1"

# 检查项目路径是否存在
if [ ! -d "$PROJECT_PATH" ]; then
    echo "❌ 错误: 项目路径不存在: $PROJECT_PATH"
    exit 1
fi

# 检查是否为Java项目
if [ ! -f "$PROJECT_PATH/pom.xml" ] && [ ! -f "$PROJECT_PATH/build.gradle" ] && [ ! -f "$PROJECT_PATH/build.gradle.kts" ]; then
    # 检查是否有.java文件
    if ! find "$PROJECT_PATH" -name "*.java" -type f | head -1 | grep -q .; then
        echo "⚠️  警告: 未检测到Java项目文件 (pom.xml, build.gradle, *.java)"
        echo "是否继续扫描? (y/N)"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            echo "扫描已取消"
            exit 0
        fi
    fi
fi

echo "🚀 启动Java安全扫描器..."
echo "📁 项目路径: $PROJECT_PATH"
echo ""

# 运行Joern扫描器
cd "$SCRIPT_DIR"
joern --script "$SCANNER_SCRIPT" -- "$PROJECT_PATH"

echo ""
echo "✅ 扫描完成!"
