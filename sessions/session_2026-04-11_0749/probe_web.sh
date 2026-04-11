#!/bin/bash

TARGET="zhhovo.top"
IP="39.106.227.104"
OUTPUT_FILE="/project/ovogogogo/sessions/session_2026-04-11_0749/web.txt"

echo "Web资产探测结果 - $(date)" > "$OUTPUT_FILE"
echo "================================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# 探测常见端口和URL
declare -a urls=(
    "http://$TARGET"
    "https://$TARGET"
    "http://www.$TARGET"
    "https://www.$TARGET"
    "http://$IP"
    "https://$IP"
    "http://$TARGET:8080"
    "https://$TARGET:8443"
    "http://www.$TARGET:8080"
    "https://www.$TARGET:8443"
    "http://$IP:8080"
    "https://$IP:8443"
)

for url in "${urls[@]}"; do
    echo "探测: $url" >> "$OUTPUT_FILE"
    echo "--------------------------------" >> "$OUTPUT_FILE"
    
    # 使用curl获取响应头
    response=$(curl -s -I -L --max-time 10 "$url" 2>&1)
    if [ $? -eq 0 ]; then
        echo "响应头:" >> "$OUTPUT_FILE"
        echo "$response" >> "$OUTPUT_FILE"
        
        # 获取标题
        title=$(curl -s -L --max-time 10 "$url" | grep -o '<title>[^<]*</title>' | sed 's/<title>//;s/<\/title>//')
        if [ -n "$title" ]; then
            echo "标题: $title" >> "$OUTPUT_FILE"
        fi
        
        # 获取更多技术栈信息
        echo "" >> "$OUTPUT_FILE"
        echo "技术栈信息:" >> "$OUTPUT_FILE"
        
        # 获取详细的响应信息
        curl -s -I -L --max-time 10 "$url" | grep -iE "(server|x-powered-by|x-generator|content-type|location|set-cookie)" >> "$OUTPUT_FILE" 2>/dev/null
        
        # 检查特定技术栈
        echo "" >> "$OUTPUT_FILE"
        echo "特征检查:" >> "$OUTPUT_FILE"
        content=$(curl -s -L --max-time 10 "$url")
        
        if echo "$content" | grep -i "wordpress" > /dev/null; then
            echo "  ✓ 检测到 WordPress" >> "$OUTPUT_FILE"
        fi
        if echo "$content" | grep -i "jquery" > /dev/null; then
            echo "  ✓ 检测到 jQuery" >> "$OUTPUT_FILE"
        fi
        if echo "$content" | grep -i "bootstrap" > /dev/null; then
            echo "  ✓ 检测到 Bootstrap" >> "$OUTPUT_FILE"
        fi
        if echo "$content" | grep -i "react" > /dev/null; then
            echo "  ✓ 检测到 React" >> "$OUTPUT_FILE"
        fi
        if echo "$content" | grep -i "vue" > /dev/null; then
            echo "  ✓ 检测到 Vue.js" >> "$OUTPUT_FILE"
        fi
        if echo "$content" | grep -i "nginx" > /dev/null; then
            echo "  ✓ 检测到 Nginx" >> "$OUTPUT_FILE"
        fi
        if echo "$content" | grep -i "apache" > /dev/null; then
            echo "  ✓ 检测到 Apache" >> "$OUTPUT_FILE"
        fi
    else
        echo "不可达或超时" >> "$OUTPUT_FILE"
    fi
    
    echo "" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
done

echo "探测完成" >> "$OUTPUT_FILE"
