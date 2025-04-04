import os
import re
import subprocess
import signal
import time
import asyncio
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class StringResult(BaseModel):
    """字符串分析结果"""
    offset: int = Field(..., description="字符串在文件中的偏移量")
    string: str = Field(..., description="提取的字符串")
    length: int = Field(..., description="字符串长度")
    encoding: str = Field(..., description="字符串编码")
    section: Optional[str] = Field(None, description="字符串所在节区")
    is_ascii: bool = Field(..., description="是否为ASCII字符串")
    is_unicode: bool = Field(..., description="是否为Unicode字符串")
    is_utf8: bool = Field(..., description="是否为UTF-8字符串")
    is_utf16: bool = Field(..., description="是否为UTF-16字符串")
    is_printable: bool = Field(..., description="是否为可打印字符串")
    is_url: bool = Field(..., description="是否为URL")
    is_path: bool = Field(..., description="是否为路径")
    is_command: bool = Field(..., description="是否为命令")
    is_ip: bool = Field(..., description="是否为IP地址")
    is_email: bool = Field(..., description="是否为邮箱地址")
    is_guid: bool = Field(..., description="是否为GUID")
    is_hash: bool = Field(..., description="是否为哈希值")
    is_base64: bool = Field(..., description="是否为Base64编码")
    is_hex: bool = Field(..., description="是否为十六进制")
    is_binary: bool = Field(..., description="是否为二进制数据")
    is_suspicious: bool = Field(..., description="是否为可疑字符串")

class StringsAnalysisResult(BaseModel):
    """字符串分析结果"""
    file_path: str = Field(..., description="文件路径")
    total_strings: int = Field(..., description="字符串总数")
    ascii_strings: int = Field(..., description="ASCII字符串数量")
    unicode_strings: int = Field(..., description="Unicode字符串数量")
    utf8_strings: int = Field(..., description="UTF-8字符串数量")
    utf16_strings: int = Field(..., description="UTF-16字符串数量")
    printable_strings: int = Field(..., description="可打印字符串数量")
    url_strings: int = Field(..., description="URL字符串数量")
    path_strings: int = Field(..., description="路径字符串数量")
    command_strings: int = Field(..., description="命令字符串数量")
    ip_strings: int = Field(..., description="IP地址字符串数量")
    email_strings: int = Field(..., description="邮箱地址字符串数量")
    guid_strings: int = Field(..., description="GUID字符串数量")
    hash_strings: int = Field(..., description="哈希值字符串数量")
    base64_strings: int = Field(..., description="Base64编码字符串数量")
    hex_strings: int = Field(..., description="十六进制字符串数量")
    binary_strings: int = Field(..., description="二进制数据字符串数量")
    suspicious_strings: int = Field(..., description="可疑字符串数量")
    strings: List[StringResult] = Field(..., description="字符串列表")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="元数据")

async def analyze_strings(
    file_path: str,
    min_length: int = 4,
    encoding: str = "utf-8",
    section: Optional[str] = None,
    timeout: int = 60
) -> StringsAnalysisResult:
    """
    分析文件中的字符串
    
    Args:
        file_path: 文件路径
        min_length: 最小字符串长度
        encoding: 字符串编码
        section: 节区名称
        timeout: 超时时间(秒)
        
    Returns:
        StringsAnalysisResult: 字符串分析结果
    """
    process = None
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
            
        # 初始化结果
        result = StringsAnalysisResult(
            file_path=file_path,
            total_strings=0,
            ascii_strings=0,
            unicode_strings=0,
            utf8_strings=0,
            utf16_strings=0,
            printable_strings=0,
            url_strings=0,
            path_strings=0,
            command_strings=0,
            ip_strings=0,
            email_strings=0,
            guid_strings=0,
            hash_strings=0,
            base64_strings=0,
            hex_strings=0,
            binary_strings=0,
            suspicious_strings=0,
            strings=[],
            metadata={
                "min_length": min_length,
                "encoding": encoding,
                "section": section,
                "timeout": timeout
            }
        )
        
        # 使用strings命令提取字符串
        cmd = ["strings", "-a", "-n", str(min_length), file_path]
        if section:
            cmd.extend(["-t", "x", "-s", section])
            
        # 启动进程
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            preexec_fn=os.setsid  # 创建新进程组
        )
        
        # 等待进程完成或超时
        start_time = time.time()
        while process.poll() is None:
            if time.time() - start_time > timeout:
                # 超时，终止进程组
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except Exception:
                    pass
                raise TimeoutError(f"字符串分析超时: {timeout}秒")
            await asyncio.sleep(0.1)
        
        # 获取输出
        stdout, stderr = process.communicate()
        
        # 检查返回码
        if process.returncode != 0:
            raise Exception(f"strings命令执行失败: {stderr}")
            
        # 解析输出
        for line in stdout.splitlines():
            try:
                # 解析偏移量和字符串
                if section:
                    offset_str, string = line.split(" ", 1)
                    offset = int(offset_str, 16)
                else:
                    offset = len(result.strings)
                    string = line
                    
                # 创建字符串结果
                string_result = StringResult(
                    offset=offset,
                    string=string,
                    length=len(string),
                    encoding=encoding,
                    section=section,
                    is_ascii=all(ord(c) < 128 for c in string),
                    is_unicode=any(ord(c) > 127 for c in string),
                    is_utf8=is_utf8(string),
                    is_utf16=is_utf16(string),
                    is_printable=all(c.isprintable() for c in string),
                    is_url=is_url(string),
                    is_path=is_path(string),
                    is_command=is_command(string),
                    is_ip=is_ip(string),
                    is_email=is_email(string),
                    is_guid=is_guid(string),
                    is_hash=is_hash(string),
                    is_base64=is_base64(string),
                    is_hex=is_hex(string),
                    is_binary=is_binary(string),
                    is_suspicious=is_suspicious(string)
                )
                
                # 更新统计信息
                result.strings.append(string_result)
                result.total_strings += 1
                
                if string_result.is_ascii:
                    result.ascii_strings += 1
                if string_result.is_unicode:
                    result.unicode_strings += 1
                if string_result.is_utf8:
                    result.utf8_strings += 1
                if string_result.is_utf16:
                    result.utf16_strings += 1
                if string_result.is_printable:
                    result.printable_strings += 1
                if string_result.is_url:
                    result.url_strings += 1
                if string_result.is_path:
                    result.path_strings += 1
                if string_result.is_command:
                    result.command_strings += 1
                if string_result.is_ip:
                    result.ip_strings += 1
                if string_result.is_email:
                    result.email_strings += 1
                if string_result.is_guid:
                    result.guid_strings += 1
                if string_result.is_hash:
                    result.hash_strings += 1
                if string_result.is_base64:
                    result.base64_strings += 1
                if string_result.is_hex:
                    result.hex_strings += 1
                if string_result.is_binary:
                    result.binary_strings += 1
                if string_result.is_suspicious:
                    result.suspicious_strings += 1
                    
            except Exception as e:
                print(f"解析字符串失败: {e}")
                continue
                
        return result
        
    except Exception as e:
        raise Exception(f"字符串分析失败: {e}")
        
    finally:
        # 确保进程被终止
        if process and process.poll() is None:
            try:
                # 终止进程组
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                # 等待进程结束
                process.wait(timeout=5)
            except Exception:
                # 如果进程仍然存在，强制终止
                try:
                    process.kill()
                except Exception:
                    pass

def is_utf8(string: str) -> bool:
    """判断是否为UTF-8编码"""
    try:
        string.encode('utf-8').decode('utf-8')
        return True
    except UnicodeError:
        return False

def is_utf16(string: str) -> bool:
    """判断是否为UTF-16编码"""
    try:
        string.encode('utf-16').decode('utf-16')
        return True
    except UnicodeError:
        return False

def is_url(string: str) -> bool:
    """判断是否为URL"""
    url_pattern = r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
    return bool(re.match(url_pattern, string.strip()))

def is_path(string: str) -> bool:
    """判断是否为路径"""
    path_pattern = r'^([a-zA-Z]:\\|\/)([\w\-\. \\\/]+)$'
    return bool(re.match(path_pattern, string.strip()))

def is_command(string: str) -> bool:
    """判断是否为命令"""
    # 提取文件名
    string = string.strip().lower()
    filename = string.split('\\')[-1] if '\\' in string else string.split('/')[-1] if '/' in string else string
    
    # 检查文件扩展名
    command_exts = {'.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.sh', '.bash'}
    return any(filename.endswith(ext) for ext in command_exts)

def is_ip(string: str) -> bool:
    """判断是否为IP地址"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, string.strip()):
        return False
    return all(0 <= int(x) <= 255 for x in string.strip().split('.'))

def is_email(string: str) -> bool:
    """判断是否为邮箱地址"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, string.strip()))

def is_guid(string: str) -> bool:
    """判断是否为GUID"""
    guid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    return bool(re.match(guid_pattern, string.strip().lower()))

def is_hash(string: str) -> bool:
    """判断是否为哈希值"""
    hash_patterns = {
        'MD5': r'^[a-f0-9]{32}$',
        'SHA1': r'^[a-f0-9]{40}$',
        'SHA256': r'^[a-f0-9]{64}$',
        'SHA512': r'^[a-f0-9]{128}$'
    }
    string = string.strip().lower()
    return any(re.match(pattern, string) for pattern in hash_patterns.values())

def is_base64(string: str) -> bool:
    """判断是否为Base64编码"""
    string = string.strip()
    # 忽略太短的字符串
    if len(string) < 8:
        return False
        
    base64_pattern = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
    if not re.match(base64_pattern, string):
        return False
        
    try:
        # 尝试解码
        import base64
        decoded = base64.b64decode(string)
        # 检查解码后的数据是否为可打印字符串
        return all(32 <= byte <= 126 for byte in decoded)
    except Exception:
        return False

def is_hex(string: str) -> bool:
    """判断是否为十六进制"""
    string = string.strip().lower()
    # 移除0x前缀
    if string.startswith('0x'):
        string = string[2:]
    # 检查长度是否为偶数（每个字节由两个十六进制字符表示）
    if len(string) % 2 != 0:
        return False
    hex_pattern = r'^[0-9a-f]+$'
    return bool(re.match(hex_pattern, string))

def is_binary(string: str) -> bool:
    """判断是否为二进制数据"""
    string = string.strip()
    # 忽略太短的字符串
    if len(string) < 8:
        return False
    # 必须是8的倍数（每个字节8位）
    if len(string) % 8 != 0:
        return False
    binary_pattern = r'^[01]+$'
    return bool(re.match(binary_pattern, string))

def is_suspicious(string: str) -> bool:
    """判断是否为可疑字符串"""
    suspicious_patterns = [
        r'cmd\.exe',
        r'powershell',
        r'wscript',
        r'cscript',
        r'mshta',
        r'regsvr32',
        r'rundll32',
        r'certutil',
        r'bitsadmin',
        r'msbuild',
        r'msiexec',
        r'netcat',
        r'ncat',
        r'socat',
        r'nc',
        r'telnet',
        r'ftp',
        r'ssh',
        r'scp',
        r'wget',
        r'curl',
        r'certificate',
        r'private key',
        r'password',
        r'admin',
        r'root',
        r'system',
        r'administrator',
        r'sudo',
        r'su',
        r'chmod',
        r'chown',
        r'mount',
        r'umount',
        r'format',
        r'delete',
        r'remove',
        r'drop',
        r'create',
        r'insert',
        r'update',
        r'select',
        r'exec',
        r'eval',
        r'system',
        r'shell',
        r'command',
        r'cmd',
        r'powershell',
        r'bash',
        r'sh',
        r'zsh',
        r'ksh',
        r'csh',
        r'tcsh',
        r'fish',
        r'python',
        r'perl',
        r'ruby',
        r'php',
        r'javascript',
        r'vbscript',
        r'jscript',
        r'vbs',
        r'js',
        r'wsf',
        r'hta',
        r'url',
        r'http',
        r'https',
        r'ftp',
        r'sftp',
        r'ssh',
        r'scp',
        r'telnet',
        r'rdp',
        r'vnc',
        r'remote',
        r'desktop',
        r'terminal',
        r'console'
    ]
    
    return any(re.search(pattern, string, re.IGNORECASE) for pattern in suspicious_patterns) 