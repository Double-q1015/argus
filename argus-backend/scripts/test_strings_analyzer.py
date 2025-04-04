import os
import sys
import asyncio

# 添加项目根目录到系统路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.strings_analyzer import analyze_strings, StringResult, StringsAnalysisResult

async def test_analyze_strings():
    """测试字符串分析功能"""
    print("\n=== 测试字符串分析 ===")
    
    # 创建测试文件
    test_file = "/tmp/strings_test.txt"
    test_content = """
    Hello World! 这是一个测试文件。
    https://example.com
    C:\\Windows\\System32\\cmd.exe
    192.168.1.1
    test@example.com
    550e8400-e29b-41d4-a716-446655440000
    d41d8cd98f00b204e9800998ecf8427e
    SGVsbG8gV29ybGQ=
    0x1234ABCD
    10101010
    """
    
    try:
        # 写入测试文件
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(test_content)
            
        print(f"测试文件已创建: {test_file}")
        
        # 分析字符串
        result = await analyze_strings(test_file)
        
        # 打印分析结果
        print("\n分析结果:")
        print(f"文件路径: {result.file_path}")
        print(f"字符串总数: {result.total_strings}")
        print(f"ASCII字符串数量: {result.ascii_strings}")
        print(f"Unicode字符串数量: {result.unicode_strings}")
        print(f"UTF-8字符串数量: {result.utf8_strings}")
        print(f"UTF-16字符串数量: {result.utf16_strings}")
        print(f"可打印字符串数量: {result.printable_strings}")
        print(f"URL字符串数量: {result.url_strings}")
        print(f"路径字符串数量: {result.path_strings}")
        print(f"命令字符串数量: {result.command_strings}")
        print(f"IP地址字符串数量: {result.ip_strings}")
        print(f"邮箱地址字符串数量: {result.email_strings}")
        print(f"GUID字符串数量: {result.guid_strings}")
        print(f"哈希值字符串数量: {result.hash_strings}")
        print(f"Base64编码字符串数量: {result.base64_strings}")
        print(f"十六进制字符串数量: {result.hex_strings}")
        print(f"二进制数据字符串数量: {result.binary_strings}")
        print(f"可疑字符串数量: {result.suspicious_strings}")
        
        print("\n字符串列表:")
        for string in result.strings:
            print(f"\n偏移量: {string.offset}")
            print(f"字符串: {string.string}")
            print(f"长度: {string.length}")
            print(f"编码: {string.encoding}")
            print(f"节区: {string.section}")
            print(f"是否为ASCII: {string.is_ascii}")
            print(f"是否为Unicode: {string.is_unicode}")
            print(f"是否为UTF-8: {string.is_utf8}")
            print(f"是否为UTF-16: {string.is_utf16}")
            print(f"是否为可打印: {string.is_printable}")
            print(f"是否为URL: {string.is_url}")
            print(f"是否为路径: {string.is_path}")
            print(f"是否为命令: {string.is_command}")
            print(f"是否为IP地址: {string.is_ip}")
            print(f"是否为邮箱地址: {string.is_email}")
            print(f"是否为GUID: {string.is_guid}")
            print(f"是否为哈希值: {string.is_hash}")
            print(f"是否为Base64编码: {string.is_base64}")
            print(f"是否为十六进制: {string.is_hex}")
            print(f"是否为二进制数据: {string.is_binary}")
            print(f"是否为可疑字符串: {string.is_suspicious}")
            
    except Exception as e:
        print(f"测试失败: {e}")
        
    finally:
        # 清理测试文件
        if os.path.exists(test_file):
            os.remove(test_file)
            print(f"\n测试文件已删除: {test_file}")

if __name__ == "__main__":
    asyncio.run(test_analyze_strings()) 