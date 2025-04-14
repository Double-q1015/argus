import os
import sys
import asyncio
import tempfile

# 添加项目根目录到系统路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.magic_analyzer import get_file_type, MagicResult

async def test_magic_analyzer():
    """测试文件类型分析功能"""
    print("\n=== 测试文件类型分析 ===")
    
    # 创建临时目录
    with tempfile.TemporaryDirectory() as temp_dir:
        # 测试文件列表
        test_files = {
            # 文本文件
            "text.txt": "这是一个文本文件。\nHello World!",
            
            # Python脚本
            "script.py": """#!/usr/bin/env python3
print("Hello World!")
""",
            
            # Shell脚本
            "script.sh": """#!/bin/bash
echo "Hello World!"
""",
            
            # HTML文件
            "webpage.html": """<!DOCTYPE html>
<html><body><h1>Hello World!</h1></body></html>
""",
            
            # XML文件
            "data.xml": """<?xml version="1.0"?>
<root><message>Hello World!</message></root>
""",
            
            # JSON文件
            "data.json": """{"message": "Hello World!"}""",
            
            # YAML文件
            "config.yaml": """message: Hello World!""",
            
            # Markdown文件
            "doc.md": """# Hello World!""",
            
            # 配置文件
            "app.conf": """[app]
name=Hello World
""",
            
            # 日志文件
            "app.log": """2024-01-01 00:00:00 INFO Hello World""",
            
            # 空文件
            "empty.txt": "",
            
            # 隐藏文件
            ".hidden": "这是一个隐藏文件",
            
            # 二进制文件
            "binary.dat": bytes([0x00, 0x01, 0x02, 0x03])
        }
        
        # 创建并测试每个文件
        for filename, content in test_files.items():
            file_path = os.path.join(temp_dir, filename)
            
            # 写入文件内容
            mode = "w" if isinstance(content, str) else "wb"
            with open(file_path, mode) as f:
                f.write(content)
                
            # 设置可执行权限（对于脚本文件）
            if filename.endswith((".py", ".sh")):
                os.chmod(file_path, 0o755)
                
            print(f"\n测试文件: {filename}")
            
            # 分析文件类型
            result = await get_file_type(file_path)
            
            # 打印分析结果
            print(f"MIME类型: {result.mime_type}")
            print(f"文件类型: {result.file_type}")
            print(f"是否为文本文件: {result.is_text}")
            print(f"是否为二进制文件: {result.is_binary}")
            print(f"是否为可执行文件: {result.is_executable}")
            print(f"是否为压缩文件: {result.is_archive}")
            print(f"是否为文档文件: {result.is_document}")
            print(f"是否为图片文件: {result.is_image}")
            print(f"是否为音频文件: {result.is_audio}")
            print(f"是否为视频文件: {result.is_video}")
            print(f"是否为脚本文件: {result.is_script}")
            print(f"是否为PE文件: {result.is_pe}")
            print(f"是否为ELF文件: {result.is_elf}")
            print(f"是否为Mach-O文件: {result.is_mach_o}")
            print(f"是否为PDF文件: {result.is_pdf}")
            print(f"是否为Office文件: {result.is_office}")
            print(f"是否为Java文件: {result.is_java}")
            print(f"是否为Python文件: {result.is_python}")
            print(f"是否为Shell脚本: {result.is_shell}")
            print(f"是否为PowerShell脚本: {result.is_powershell}")
            print(f"是否为JavaScript文件: {result.is_javascript}")
            print(f"是否为HTML文件: {result.is_html}")
            print(f"是否为XML文件: {result.is_xml}")
            print(f"是否为JSON文件: {result.is_json}")
            print(f"是否为YAML文件: {result.is_yaml}")
            print(f"是否为Markdown文件: {result.is_markdown}")
            print(f"是否为配置文件: {result.is_config}")
            print(f"是否为日志文件: {result.is_log}")
            print(f"是否为备份文件: {result.is_backup}")
            print(f"是否为临时文件: {result.is_temp}")
            print(f"是否为隐藏文件: {result.is_hidden}")
            print(f"是否为系统文件: {result.is_system}")
            print(f"是否为加密文件: {result.is_encrypted}")
            print(f"是否为压缩文件: {result.is_compressed}")
            print(f"是否为损坏文件: {result.is_corrupted}")
            print(f"是否为空文件: {result.is_empty}")
            print(f"是否为符号链接: {result.is_symlink}")
            print(f"是否为命名管道: {result.is_fifo}")
            print(f"是否为套接字: {result.is_socket}")
            print(f"是否为块设备: {result.is_block}")
            print(f"是否为字符设备: {result.is_char}")
            print(f"是否为未知类型: {result.is_unknown}")

if __name__ == "__main__":
    asyncio.run(test_magic_analyzer()) 