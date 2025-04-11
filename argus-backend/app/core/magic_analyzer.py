import magic
import os
from typing import Dict, Any
from pydantic import BaseModel

class MagicResult(BaseModel):
    """Magic分析结果"""
    mime_type: str = ""  # MIME类型
    file_type: str = ""  # 文件类型描述
    is_text: bool = False  # 是否为文本文件
    is_binary: bool = False  # 是否为二进制文件
    is_executable: bool = False  # 是否为可执行文件
    is_archive: bool = False  # 是否为压缩文件
    is_document: bool = False  # 是否为文档文件
    is_image: bool = False  # 是否为图片文件
    is_audio: bool = False  # 是否为音频文件
    is_video: bool = False  # 是否为视频文件
    is_script: bool = False  # 是否为脚本文件
    is_pe: bool = False  # 是否为PE文件
    is_elf: bool = False  # 是否为ELF文件
    is_mach_o: bool = False  # 是否为Mach-O文件
    is_pdf: bool = False  # 是否为PDF文件
    is_office: bool = False  # 是否为Office文件
    is_java: bool = False  # 是否为Java文件
    is_python: bool = False  # 是否为Python文件
    is_shell: bool = False  # 是否为Shell脚本
    is_powershell: bool = False  # 是否为PowerShell脚本
    is_javascript: bool = False  # 是否为JavaScript文件
    is_html: bool = False  # 是否为HTML文件
    is_xml: bool = False  # 是否为XML文件
    is_json: bool = False  # 是否为JSON文件
    is_yaml: bool = False  # 是否为YAML文件
    is_markdown: bool = False  # 是否为Markdown文件
    is_config: bool = False  # 是否为配置文件
    is_log: bool = False  # 是否为日志文件
    is_backup: bool = False  # 是否为备份文件
    is_temp: bool = False  # 是否为临时文件
    is_hidden: bool = False  # 是否为隐藏文件
    is_system: bool = False  # 是否为系统文件
    is_encrypted: bool = False  # 是否为加密文件
    is_compressed: bool = False  # 是否为压缩文件
    is_corrupted: bool = False  # 是否为损坏文件
    is_empty: bool = False  # 是否为空文件
    is_symlink: bool = False  # 是否为符号链接
    is_fifo: bool = False  # 是否为命名管道
    is_socket: bool = False  # 是否为套接字
    is_block: bool = False  # 是否为块设备
    is_char: bool = False  # 是否为字符设备
    is_unknown: bool = False  # 是否为未知类型

    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {k: v for k, v in self.dict(by_alias=True).items() if v is not None}

async def perform_magic_analysis(file_path: str) -> MagicResult:
    """
    使用magic库识别文件类型
    
    Args:
        file_path: 文件路径
        
    Returns:
        MagicResult: 文件类型分析结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
            
        # 初始化magic
        mime = magic.Magic(mime=True)
        file_type = magic.Magic()
        
        # 获取MIME类型和文件类型描述
        mime_type = mime.from_file(file_path)
        file_type_desc = file_type.from_file(file_path)
        
        # 创建结果对象
        result = MagicResult(
            mime_type=mime_type,
            file_type=file_type_desc
        )
        
        # 检查文件大小
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            result.is_empty = True
            return result
            
        # 检查文件属性
        if os.path.islink(file_path):
            result.is_symlink = True
        if os.path.isfifo(file_path):
            result.is_fifo = True
        if os.path.issock(file_path):
            result.is_socket = True
        if os.path.isblk(file_path):
            result.is_block = True
        if os.path.ischr(file_path):
            result.is_char = True
            
        # 检查是否为隐藏文件
        if os.path.basename(file_path).startswith('.'):
            result.is_hidden = True
            
        # 根据MIME类型和文件类型描述判断文件类型
        mime_type_lower = mime_type.lower()
        file_type_lower = file_type_desc.lower()
        
        # 文本文件
        if "text" in mime_type_lower or "text" in file_type_lower:
            result.is_text = True
            
        # 二进制文件
        if "application/octet-stream" in mime_type_lower and not result.is_text:
            result.is_binary = True
            
        # 可执行文件
        if any(x in file_type_lower for x in ["executable", "pe32", "elf", "mach-o"]):
            result.is_executable = True
            
        # 压缩文件
        if any(x in mime_type_lower for x in ["zip", "tar", "gz", "7z", "rar"]):
            result.is_archive = True
            result.is_compressed = True
            
        # 文档文件
        if any(x in mime_type_lower for x in ["pdf", "msword", "vnd.ms-excel", "vnd.ms-powerpoint"]):
            result.is_document = True
            
        # 图片文件
        if "image" in mime_type_lower:
            result.is_image = True
            
        # 音频文件
        if "audio" in mime_type_lower:
            result.is_audio = True
            
        # 视频文件
        if "video" in mime_type_lower:
            result.is_video = True
            
        # 脚本文件
        if any(x in file_type_lower for x in ["python", "shell", "perl", "ruby", "javascript"]):
            result.is_script = True
            
        # PE文件
        if "pe32" in file_type_lower or "pe64" in file_type_lower:
            result.is_pe = True
            
        # ELF文件
        if "elf" in file_type_lower:
            result.is_elf = True
            
        # Mach-O文件
        if "mach-o" in file_type_lower:
            result.is_mach_o = True
            
        # PDF文件
        if "pdf" in mime_type_lower:
            result.is_pdf = True
            
        # Office文件
        if any(x in mime_type_lower for x in ["msword", "vnd.ms-excel", "vnd.ms-powerpoint"]):
            result.is_office = True
            
        # Java文件
        if "java" in file_type_lower or "class" in file_type_lower:
            result.is_java = True
            
        # Python文件
        if "python" in file_type_lower:
            result.is_python = True
            
        # Shell脚本
        if "shell script" in file_type_lower:
            result.is_shell = True
            
        # PowerShell脚本
        if "powershell" in file_type_lower:
            result.is_powershell = True
            
        # JavaScript文件
        if "javascript" in file_type_lower:
            result.is_javascript = True
            
        # HTML文件
        if "html" in mime_type_lower:
            result.is_html = True
            
        # XML文件
        if "xml" in mime_type_lower:
            result.is_xml = True
            
        # JSON文件
        if "json" in mime_type_lower:
            result.is_json = True
            
        # YAML文件
        if "yaml" in file_type_lower:
            result.is_yaml = True
            
        # Markdown文件
        if "markdown" in file_type_lower:
            result.is_markdown = True
            
        # 配置文件
        if any(x in file_type_lower for x in ["config", "ini", "conf", "cfg"]):
            result.is_config = True
            
        # 日志文件
        if "log" in file_type_lower:
            result.is_log = True
            
        # 备份文件
        if any(x in file_type_lower for x in ["backup", "bak", "old"]):
            result.is_backup = True
            
        # 临时文件
        if any(x in file_type_lower for x in ["temp", "tmp", "swp"]):
            result.is_temp = True
            
        # 系统文件
        if any(x in file_type_lower for x in ["system", "dll", "sys"]):
            result.is_system = True
            
        # 加密文件
        if "encrypted" in file_type_lower:
            result.is_encrypted = True
            
        # 损坏文件
        if "corrupted" in file_type_lower:
            result.is_corrupted = True
            
        # 未知类型
        if mime_type == "application/octet-stream" and not result.is_binary and not result.is_text:
            result.is_unknown = True
            
        return result
        
    except Exception as e:
        # 发生错误时返回未知类型
        return MagicResult(
            mime_type="application/octet-stream",
            file_type="unknown",
            is_unknown=True,
            is_corrupted=True
        ) 