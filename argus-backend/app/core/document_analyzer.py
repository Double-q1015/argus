from typing import List, Optional, Dict, Any
from datetime import datetime
import os
import fitz  # PyMuPDF
from pydantic import BaseModel, Field
import asyncio
from pathlib import Path
import math
from PIL import Image
from PIL.ExifTags import TAGS
import piexif
import piexif.helper

class PDFMetadata(BaseModel):
    """PDF文件元数据"""
    file_path: str
    file_size: int
    page_count: int
    title: Optional[str] = None
    author: Optional[str] = None
    subject: Optional[str] = None
    keywords: Optional[str] = None
    creator: Optional[str] = None
    producer: Optional[str] = None
    creation_date: Optional[datetime] = None
    modification_date: Optional[datetime] = None
    is_encrypted: bool = False
    has_images: bool = False
    has_forms: bool = False
    has_links: bool = False
    has_bookmarks: bool = False
    has_javascript: bool = False
    has_embedded_files: bool = False

class PDFContent(BaseModel):
    """PDF文件内容"""
    text: str = ""
    images: List[Dict[str, Any]] = []
    links: List[Dict[str, Any]] = []
    bookmarks: List[Dict[str, Any]] = []
    embedded_files: List[Dict[str, Any]] = []

class PDFAnalysisResult(BaseModel):
    """PDF分析结果"""
    metadata: PDFMetadata
    content: PDFContent
    vulnerabilities: List[str] = []
    error_message: Optional[str] = None

async def analyze_pdf(file_path: str, timeout: int = 60) -> PDFAnalysisResult:
    """
    分析PDF文件
    
    Args:
        file_path: PDF文件路径
        timeout: 分析超时时间（秒）
        
    Returns:
        PDFAnalysisResult: PDF分析结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return PDFAnalysisResult(
                metadata=PDFMetadata(file_path=file_path, file_size=0, page_count=0),
                content=PDFContent(),
                vulnerabilities=["文件不存在"],
                error_message="文件不存在"
            )

        # 获取文件信息
        file_size = os.path.getsize(file_path)
        
        # 打开PDF文件
        doc = fitz.open(file_path)
        
        # 提取元数据
        metadata = doc.metadata
        page_count = len(doc)
        
        # 创建元数据对象
        pdf_metadata = PDFMetadata(
            file_path=file_path,
            file_size=file_size,
            page_count=page_count,
            title=metadata.get("title"),
            author=metadata.get("author"),
            subject=metadata.get("subject"),
            keywords=metadata.get("keywords"),
            creator=metadata.get("creator"),
            producer=metadata.get("producer"),
            creation_date=metadata.get("creationDate"),
            modification_date=metadata.get("modDate"),
            is_encrypted=doc.is_encrypted,
            has_images=False,  # 将在内容分析中更新
            has_forms=False,   # 将在内容分析中更新
            has_links=False,   # 将在内容分析中更新
            has_bookmarks=False,  # 将在内容分析中更新
            has_javascript=False,  # 将在内容分析中更新
            has_embedded_files=False  # 将在内容分析中更新
        )
        
        # 初始化内容对象
        content = PDFContent()
        vulnerabilities = []
        
        # 提取文本内容
        for page in doc:
            content.text += page.get_text()
        
        # 提取图片
        for page_num in range(page_count):
            page = doc[page_num]
            image_list = page.get_images()
            if image_list:
                pdf_metadata.has_images = True
                for img_index, img in enumerate(image_list):
                    xref = img[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    image_ext = base_image["ext"]
                    
                    content.images.append({
                        "page": page_num + 1,
                        "index": img_index,
                        "format": image_ext,
                        "size": len(image_bytes)
                    })
        
        # 提取链接
        for page_num in range(page_count):
            page = doc[page_num]
            links = page.get_links()
            if links:
                pdf_metadata.has_links = True
                for link in links:
                    content.links.append({
                        "page": page_num + 1,
                        "type": link.get("kind"),
                        "uri": link.get("uri"),
                        "rect": link.get("rect")
                    })
        
        # 提取书签
        toc = doc.get_toc()
        if toc:
            pdf_metadata.has_bookmarks = True
            for level, title, page in toc:
                content.bookmarks.append({
                    "level": level,
                    "title": title,
                    "page": page + 1
                })
        
        # 检查JavaScript
        if doc.has_javascript():
            pdf_metadata.has_javascript = True
            vulnerabilities.append("包含JavaScript代码")
        
        # 提取嵌入文件
        for file in doc.embeds():
            pdf_metadata.has_embedded_files = True
            content.embedded_files.append({
                "name": file["name"],
                "size": file["size"],
                "type": file["type"]
            })
        
        # 检查表单
        if doc.has_form():
            pdf_metadata.has_forms = True
        
        # 关闭文档
        doc.close()
        
        return PDFAnalysisResult(
            metadata=pdf_metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except Exception as e:
        return PDFAnalysisResult(
            metadata=PDFMetadata(file_path=file_path, file_size=0, page_count=0),
            content=PDFContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

class ArchiveMetadata(BaseModel):
    """压缩文件元数据"""
    file_path: str
    file_size: int
    file_type: str  # zip, tar, gzip, bzip2, lzma
    total_files: int
    total_size: int
    compressed_size: int
    compression_ratio: float
    has_nested_archives: bool = False
    has_executables: bool = False
    has_scripts: bool = False
    has_suspicious_files: bool = False
    has_path_traversal: bool = False
    is_password_protected: bool = False

class ArchiveContent(BaseModel):
    """压缩文件内容"""
    files: List[Dict[str, Any]] = []
    nested_archives: List[Dict[str, Any]] = []
    executables: List[Dict[str, Any]] = []
    scripts: List[Dict[str, Any]] = []
    suspicious_files: List[Dict[str, Any]] = []

class ArchiveAnalysisResult(BaseModel):
    """压缩文件分析结果"""
    metadata: ArchiveMetadata
    content: ArchiveContent
    vulnerabilities: List[str] = []
    error_message: Optional[str] = None

async def analyze_archive(file_path: str, timeout: int = 60) -> ArchiveAnalysisResult:
    """
    分析压缩文件
    
    Args:
        file_path: 压缩文件路径
        timeout: 分析超时时间（秒）
        
    Returns:
        ArchiveAnalysisResult: 压缩文件分析结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return ArchiveAnalysisResult(
                metadata=ArchiveMetadata(
                    file_path=file_path,
                    file_size=0,
                    file_type="unknown",
                    total_files=0,
                    total_size=0,
                    compressed_size=0,
                    compression_ratio=0.0
                ),
                content=ArchiveContent(),
                vulnerabilities=["文件不存在"],
                error_message="文件不存在"
            )

        # 获取文件信息
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # 根据文件类型选择不同的分析方法
        if file_ext == '.zip':
            return await analyze_zip(file_path, file_size)
        elif file_ext == '.tar':
            return await analyze_tar(file_path, file_size)
        elif file_ext in ['.gz', '.tgz']:
            return await analyze_gzip(file_path, file_size)
        elif file_ext == '.bz2':
            return await analyze_bzip2(file_path, file_size)
        elif file_ext == '.xz':
            return await analyze_lzma(file_path, file_size)
        else:
            return ArchiveAnalysisResult(
                metadata=ArchiveMetadata(
                    file_path=file_path,
                    file_size=file_size,
                    file_type="unknown",
                    total_files=0,
                    total_size=0,
                    compressed_size=0,
                    compression_ratio=0.0
                ),
                content=ArchiveContent(),
                vulnerabilities=["不支持的文件类型"],
                error_message=f"不支持的文件类型: {file_ext}"
            )
            
    except Exception as e:
        return ArchiveAnalysisResult(
            metadata=ArchiveMetadata(
                file_path=file_path,
                file_size=0,
                file_type="unknown",
                total_files=0,
                total_size=0,
                compressed_size=0,
                compression_ratio=0.0
            ),
            content=ArchiveContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_zip(file_path: str, file_size: int) -> ArchiveAnalysisResult:
    """分析ZIP文件"""
    import zipfile
    
    content = ArchiveContent()
    vulnerabilities = []
    total_size = 0
    total_files = 0
    
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            # 检查是否加密
            is_encrypted = any(info.flag_bits & 0x1 for info in zip_ref.filelist)
            
            # 分析每个文件
            for info in zip_ref.filelist:
                total_files += 1
                total_size += info.file_size
                
                # 检查路径遍历
                if '..' in info.filename or info.filename.startswith('/'):
                    vulnerabilities.append(f"发现路径遍历: {info.filename}")
                
                # 检查文件类型
                file_ext = os.path.splitext(info.filename)[1].lower()
                
                # 记录文件信息
                file_info = {
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "type": file_ext
                }
                content.files.append(file_info)
                
                # 检查嵌套压缩文件
                if file_ext in ['.zip', '.tar', '.gz', '.bz2', '.xz']:
                    content.nested_archives.append(file_info)
                
                # 检查可执行文件
                elif file_ext in ['.exe', '.dll', '.so', '.dylib']:
                    content.executables.append(file_info)
                
                # 检查脚本文件
                elif file_ext in ['.py', '.sh', '.bat', '.ps1', '.js', '.vbs']:
                    content.scripts.append(file_info)
                
                # 检查可疑文件
                if file_ext in ['.exe', '.dll', '.so', '.dylib', '.bat', '.ps1', '.vbs']:
                    content.suspicious_files.append(file_info)
        
        # 创建元数据对象
        metadata = ArchiveMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="zip",
            total_files=total_files,
            total_size=total_size,
            compressed_size=file_size,
            compression_ratio=total_size / file_size if file_size > 0 else 0.0,
            has_nested_archives=len(content.nested_archives) > 0,
            has_executables=len(content.executables) > 0,
            has_scripts=len(content.scripts) > 0,
            has_suspicious_files=len(content.suspicious_files) > 0,
            has_path_traversal=any('..' in f["name"] or f["name"].startswith('/') for f in content.files),
            is_password_protected=is_encrypted
        )
        
        return ArchiveAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except zipfile.BadZipFile:
        return ArchiveAnalysisResult(
            metadata=ArchiveMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="zip",
                total_files=0,
                total_size=0,
                compressed_size=0,
                compression_ratio=0.0
            ),
            content=ArchiveContent(),
            vulnerabilities=["无效的ZIP文件"],
            error_message="无效的ZIP文件"
        )

async def analyze_tar(file_path: str, file_size: int) -> ArchiveAnalysisResult:
    """分析TAR文件"""
    import tarfile
    
    content = ArchiveContent()
    vulnerabilities = []
    total_size = 0
    total_files = 0
    
    try:
        with tarfile.open(file_path, 'r:*') as tar_ref:
            # 分析每个文件
            for member in tar_ref.getmembers():
                if member.isfile():
                    total_files += 1
                    total_size += member.size
                    
                    # 检查路径遍历
                    if '..' in member.name or member.name.startswith('/'):
                        vulnerabilities.append(f"发现路径遍历: {member.name}")
                    
                    # 检查文件类型
                    file_ext = os.path.splitext(member.name)[1].lower()
                    
                    # 记录文件信息
                    file_info = {
                        "name": member.name,
                        "size": member.size,
                        "compressed_size": member.size,  # TAR不压缩
                        "type": file_ext
                    }
                    content.files.append(file_info)
                    
                    # 检查嵌套压缩文件
                    if file_ext in ['.zip', '.tar', '.gz', '.bz2', '.xz']:
                        content.nested_archives.append(file_info)
                    
                    # 检查可执行文件
                    elif file_ext in ['.exe', '.dll', '.so', '.dylib']:
                        content.executables.append(file_info)
                    
                    # 检查脚本文件
                    elif file_ext in ['.py', '.sh', '.bat', '.ps1', '.js', '.vbs']:
                        content.scripts.append(file_info)
                    
                    # 检查可疑文件
                    if file_ext in ['.exe', '.dll', '.so', '.dylib', '.bat', '.ps1', '.vbs']:
                        content.suspicious_files.append(file_info)
        
        # 创建元数据对象
        metadata = ArchiveMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="tar",
            total_files=total_files,
            total_size=total_size,
            compressed_size=file_size,
            compression_ratio=1.0,  # TAR不压缩
            has_nested_archives=len(content.nested_archives) > 0,
            has_executables=len(content.executables) > 0,
            has_scripts=len(content.scripts) > 0,
            has_suspicious_files=len(content.suspicious_files) > 0,
            has_path_traversal=any('..' in f["name"] or f["name"].startswith('/') for f in content.files),
            is_password_protected=False  # TAR不支持加密
        )
        
        return ArchiveAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except tarfile.TarError:
        return ArchiveAnalysisResult(
            metadata=ArchiveMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="tar",
                total_files=0,
                total_size=0,
                compressed_size=0,
                compression_ratio=0.0
            ),
            content=ArchiveContent(),
            vulnerabilities=["无效的TAR文件"],
            error_message="无效的TAR文件"
        )

async def analyze_gzip(file_path: str, file_size: int) -> ArchiveAnalysisResult:
    """分析GZIP文件"""
    import gzip
    
    content = ArchiveContent()
    vulnerabilities = []
    
    try:
        with gzip.open(file_path, 'rb') as gz_ref:
            # 获取原始大小
            original_size = gz_ref._size
            
            # 记录文件信息
            file_info = {
                "name": os.path.basename(file_path),
                "size": original_size,
                "compressed_size": file_size,
                "type": ".gz"
            }
            content.files.append(file_info)
        
        # 创建元数据对象
        metadata = ArchiveMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="gzip",
            total_files=1,
            total_size=original_size,
            compressed_size=file_size,
            compression_ratio=original_size / file_size if file_size > 0 else 0.0,
            has_nested_archives=False,
            has_executables=False,
            has_scripts=False,
            has_suspicious_files=False,
            has_path_traversal=False,
            is_password_protected=False  # GZIP不支持加密
        )
        
        return ArchiveAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except gzip.BadGzipFile:
        return ArchiveAnalysisResult(
            metadata=ArchiveMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="gzip",
                total_files=0,
                total_size=0,
                compressed_size=0,
                compression_ratio=0.0
            ),
            content=ArchiveContent(),
            vulnerabilities=["无效的GZIP文件"],
            error_message="无效的GZIP文件"
        )

async def analyze_bzip2(file_path: str, file_size: int) -> ArchiveAnalysisResult:
    """分析BZIP2文件"""
    import bz2
    
    content = ArchiveContent()
    vulnerabilities = []
    
    try:
        with bz2.open(file_path, 'rb') as bz_ref:
            # 获取原始大小（BZIP2不提供原始大小信息）
            original_size = 0  # 无法获取
            
            # 记录文件信息
            file_info = {
                "name": os.path.basename(file_path),
                "size": original_size,
                "compressed_size": file_size,
                "type": ".bz2"
            }
            content.files.append(file_info)
        
        # 创建元数据对象
        metadata = ArchiveMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="bzip2",
            total_files=1,
            total_size=original_size,
            compressed_size=file_size,
            compression_ratio=0.0,  # 无法计算
            has_nested_archives=False,
            has_executables=False,
            has_scripts=False,
            has_suspicious_files=False,
            has_path_traversal=False,
            is_password_protected=False  # BZIP2不支持加密
        )
        
        return ArchiveAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except bz2.BadBZ2File:
        return ArchiveAnalysisResult(
            metadata=ArchiveMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="bzip2",
                total_files=0,
                total_size=0,
                compressed_size=0,
                compression_ratio=0.0
            ),
            content=ArchiveContent(),
            vulnerabilities=["无效的BZIP2文件"],
            error_message="无效的BZIP2文件"
        )

async def analyze_lzma(file_path: str, file_size: int) -> ArchiveAnalysisResult:
    """分析LZMA文件"""
    import lzma
    
    content = ArchiveContent()
    vulnerabilities = []
    
    try:
        with lzma.open(file_path, 'rb') as xz_ref:
            # 获取原始大小（LZMA不提供原始大小信息）
            original_size = 0  # 无法获取
            
            # 记录文件信息
            file_info = {
                "name": os.path.basename(file_path),
                "size": original_size,
                "compressed_size": file_size,
                "type": ".xz"
            }
            content.files.append(file_info)
        
        # 创建元数据对象
        metadata = ArchiveMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="lzma",
            total_files=1,
            total_size=original_size,
            compressed_size=file_size,
            compression_ratio=0.0,  # 无法计算
            has_nested_archives=False,
            has_executables=False,
            has_scripts=False,
            has_suspicious_files=False,
            has_path_traversal=False,
            is_password_protected=False  # LZMA不支持加密
        )
        
        return ArchiveAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except lzma.LZMAError:
        return ArchiveAnalysisResult(
            metadata=ArchiveMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="lzma",
                total_files=0,
                total_size=0,
                compressed_size=0,
                compression_ratio=0.0
            ),
            content=ArchiveContent(),
            vulnerabilities=["无效的LZMA文件"],
            error_message="无效的LZMA文件"
        )

class ScriptMetadata(BaseModel):
    """脚本文件元数据"""
    file_path: str
    file_size: int
    file_type: str  # py, sh, ps1, js, vbs
    line_count: int
    function_count: int
    class_count: int
    import_count: int
    has_suspicious_imports: bool = False
    has_suspicious_functions: bool = False
    has_suspicious_strings: bool = False
    has_network_calls: bool = False
    has_file_operations: bool = False
    has_system_calls: bool = False

class ScriptContent(BaseModel):
    """脚本文件内容"""
    text: str = ""
    functions: List[Dict[str, Any]] = []
    classes: List[Dict[str, Any]] = []
    imports: List[Dict[str, Any]] = []
    suspicious_patterns: List[Dict[str, Any]] = []

class ScriptAnalysisResult(BaseModel):
    """脚本文件分析结果"""
    metadata: ScriptMetadata
    content: ScriptContent
    vulnerabilities: List[str] = []
    error_message: Optional[str] = None

async def analyze_script(file_path: str, timeout: int = 60) -> ScriptAnalysisResult:
    """
    分析脚本文件
    
    Args:
        file_path: 脚本文件路径
        timeout: 分析超时时间（秒）
        
    Returns:
        ScriptAnalysisResult: 脚本文件分析结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return ScriptAnalysisResult(
                metadata=ScriptMetadata(
                    file_path=file_path,
                    file_size=0,
                    file_type="unknown",
                    line_count=0,
                    function_count=0,
                    class_count=0,
                    import_count=0
                ),
                content=ScriptContent(),
                vulnerabilities=["文件不存在"],
                error_message="文件不存在"
            )

        # 获取文件信息
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # 根据文件类型选择不同的分析方法
        if file_ext == '.py':
            return await analyze_python(file_path, file_size)
        elif file_ext == '.sh':
            return await analyze_shell(file_path, file_size)
        elif file_ext == '.ps1':
            return await analyze_powershell(file_path, file_size)
        elif file_ext == '.js':
            return await analyze_javascript(file_path, file_size)
        elif file_ext == '.vbs':
            return await analyze_vbs(file_path, file_size)
        else:
            return ScriptAnalysisResult(
                metadata=ScriptMetadata(
                    file_path=file_path,
                    file_size=file_size,
                    file_type="unknown",
                    line_count=0,
                    function_count=0,
                    class_count=0,
                    import_count=0
                ),
                content=ScriptContent(),
                vulnerabilities=["不支持的文件类型"],
                error_message=f"不支持的文件类型: {file_ext}"
            )
            
    except Exception as e:
        return ScriptAnalysisResult(
            metadata=ScriptMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="unknown",
                line_count=0,
                function_count=0,
                class_count=0,
                import_count=0
            ),
            content=ScriptContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_python(file_path: str, file_size: int) -> ScriptAnalysisResult:
    """分析Python脚本"""
    import ast
    
    content = ScriptContent()
    vulnerabilities = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        
        # 解析Python代码
        tree = ast.parse(source)
        
        # 统计行数
        line_count = len(source.splitlines())
        
        # 提取函数定义
        functions = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    "name": node.name,
                    "args": [arg.arg for arg in node.args.args],
                    "decorators": [d.id for d in node.decorator_list if isinstance(d, ast.Name)],
                    "lineno": node.lineno
                })
        
        # 提取类定义
        classes = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes.append({
                    "name": node.name,
                    "bases": [b.id for b in node.bases if isinstance(b, ast.Name)],
                    "decorators": [d.id for d in node.decorator_list if isinstance(d, ast.Name)],
                    "lineno": node.lineno
                })
        
        # 提取导入语句
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.append({
                        "type": "import",
                        "name": name.name,
                        "asname": name.asname,
                        "lineno": node.lineno
                    })
            elif isinstance(node, ast.ImportFrom):
                for name in node.names:
                    imports.append({
                        "type": "from",
                        "module": node.module,
                        "name": name.name,
                        "asname": name.asname,
                        "lineno": node.lineno
                    })
        
        # 检查可疑模式
        suspicious_patterns = []
        
        # 检查网络调用
        network_calls = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['requests', 'urllib', 'socket', 'httplib']:
                        network_calls = True
                        suspicious_patterns.append({
                            "type": "network_call",
                            "name": node.func.id,
                            "lineno": node.lineno
                        })
        
        # 检查文件操作
        file_operations = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['open', 'file']:
                        file_operations = True
                        suspicious_patterns.append({
                            "type": "file_operation",
                            "name": node.func.id,
                            "lineno": node.lineno
                        })
        
        # 检查系统调用
        system_calls = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['os', 'subprocess', 'system', 'exec', 'eval']:
                        system_calls = True
                        suspicious_patterns.append({
                            "type": "system_call",
                            "name": node.func.id,
                            "lineno": node.lineno
                        })
        
        # 检查可疑导入
        suspicious_imports = False
        for imp in imports:
            if imp["name"] in ['os', 'subprocess', 'socket', 'requests', 'urllib', 'httplib']:
                suspicious_imports = True
                suspicious_patterns.append({
                    "type": "suspicious_import",
                    "name": imp["name"],
                    "lineno": imp["lineno"]
                })
        
        # 更新内容对象
        content.text = source
        content.functions = functions
        content.classes = classes
        content.imports = imports
        content.suspicious_patterns = suspicious_patterns
        
        # 创建元数据对象
        metadata = ScriptMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="python",
            line_count=line_count,
            function_count=len(functions),
            class_count=len(classes),
            import_count=len(imports),
            has_suspicious_imports=suspicious_imports,
            has_suspicious_functions=any(f["name"] in ['exec', 'eval'] for f in functions),
            has_suspicious_strings=False,  # 需要更复杂的字符串分析
            has_network_calls=network_calls,
            has_file_operations=file_operations,
            has_system_calls=system_calls
        )
        
        # 添加漏洞警告
        if suspicious_imports:
            vulnerabilities.append("包含可疑的导入模块")
        if network_calls:
            vulnerabilities.append("包含网络调用")
        if file_operations:
            vulnerabilities.append("包含文件操作")
        if system_calls:
            vulnerabilities.append("包含系统调用")
        
        return ScriptAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except SyntaxError as e:
        return ScriptAnalysisResult(
            metadata=ScriptMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="python",
                line_count=0,
                function_count=0,
                class_count=0,
                import_count=0
            ),
            content=ScriptContent(),
            vulnerabilities=["语法错误"],
            error_message=f"语法错误: {str(e)}"
        )

async def analyze_shell(file_path: str, file_size: int) -> ScriptAnalysisResult:
    """分析Shell脚本"""
    content = ScriptContent()
    vulnerabilities = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        
        # 统计行数
        line_count = len(source.splitlines())
        
        # 提取函数定义
        functions = []
        for line in source.splitlines():
            if line.strip().startswith('function ') or '()' in line:
                func_name = line.strip().split()[1].split('(')[0]
                functions.append({
                    "name": func_name,
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查可疑模式
        suspicious_patterns = []
        
        # 检查网络调用
        network_calls = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['curl', 'wget', 'nc', 'netcat', 'telnet', 'ssh', 'scp']):
                network_calls = True
                suspicious_patterns.append({
                    "type": "network_call",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查文件操作
        file_operations = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['cat', 'dd', 'cp', 'mv', 'rm', '>', '>>', '<']):
                file_operations = True
                suspicious_patterns.append({
                    "type": "file_operation",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查系统调用
        system_calls = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['exec', 'eval', 'system', 'sudo', 'su']):
                system_calls = True
                suspicious_patterns.append({
                    "type": "system_call",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 更新内容对象
        content.text = source
        content.functions = functions
        content.suspicious_patterns = suspicious_patterns
        
        # 创建元数据对象
        metadata = ScriptMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="shell",
            line_count=line_count,
            function_count=len(functions),
            class_count=0,
            import_count=0,
            has_suspicious_imports=False,
            has_suspicious_functions=any(f["name"] in ['exec', 'eval'] for f in functions),
            has_suspicious_strings=False,
            has_network_calls=network_calls,
            has_file_operations=file_operations,
            has_system_calls=system_calls
        )
        
        # 添加漏洞警告
        if network_calls:
            vulnerabilities.append("包含网络调用")
        if file_operations:
            vulnerabilities.append("包含文件操作")
        if system_calls:
            vulnerabilities.append("包含系统调用")
        
        return ScriptAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except Exception as e:
        return ScriptAnalysisResult(
            metadata=ScriptMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="shell",
                line_count=0,
                function_count=0,
                class_count=0,
                import_count=0
            ),
            content=ScriptContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_powershell(file_path: str, file_size: int) -> ScriptAnalysisResult:
    """分析PowerShell脚本"""
    content = ScriptContent()
    vulnerabilities = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        
        # 统计行数
        line_count = len(source.splitlines())
        
        # 提取函数定义
        functions = []
        for line in source.splitlines():
            if line.strip().startswith('function '):
                func_name = line.strip().split()[1]
                functions.append({
                    "name": func_name,
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查可疑模式
        suspicious_patterns = []
        
        # 检查网络调用
        network_calls = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['Invoke-WebRequest', 'Invoke-RestMethod', 'Start-BitsTransfer', 'New-Object System.Net.WebClient']):
                network_calls = True
                suspicious_patterns.append({
                    "type": "network_call",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查文件操作
        file_operations = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['Get-Content', 'Set-Content', 'Add-Content', 'Copy-Item', 'Move-Item', 'Remove-Item']):
                file_operations = True
                suspicious_patterns.append({
                    "type": "file_operation",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查系统调用
        system_calls = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['Invoke-Expression', 'Start-Process', '&', '|', 'iex']):
                system_calls = True
                suspicious_patterns.append({
                    "type": "system_call",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 更新内容对象
        content.text = source
        content.functions = functions
        content.suspicious_patterns = suspicious_patterns
        
        # 创建元数据对象
        metadata = ScriptMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="powershell",
            line_count=line_count,
            function_count=len(functions),
            class_count=0,
            import_count=0,
            has_suspicious_imports=False,
            has_suspicious_functions=any(f["name"] in ['Invoke-Expression', 'iex'] for f in functions),
            has_suspicious_strings=False,
            has_network_calls=network_calls,
            has_file_operations=file_operations,
            has_system_calls=system_calls
        )
        
        # 添加漏洞警告
        if network_calls:
            vulnerabilities.append("包含网络调用")
        if file_operations:
            vulnerabilities.append("包含文件操作")
        if system_calls:
            vulnerabilities.append("包含系统调用")
        
        return ScriptAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except Exception as e:
        return ScriptAnalysisResult(
            metadata=ScriptMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="powershell",
                line_count=0,
                function_count=0,
                class_count=0,
                import_count=0
            ),
            content=ScriptContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_javascript(file_path: str, file_size: int) -> ScriptAnalysisResult:
    """分析JavaScript脚本"""
    content = ScriptContent()
    vulnerabilities = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        
        # 统计行数
        line_count = len(source.splitlines())
        
        # 提取函数定义
        functions = []
        for line in source.splitlines():
            if 'function' in line and '(' in line:
                func_name = line.strip().split('function')[1].split('(')[0].strip()
                functions.append({
                    "name": func_name,
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查可疑模式
        suspicious_patterns = []
        
        # 检查网络调用
        network_calls = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['fetch', 'XMLHttpRequest', '$.ajax', '$.get', '$.post']):
                network_calls = True
                suspicious_patterns.append({
                    "type": "network_call",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查文件操作
        file_operations = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['FileReader', 'FileWriter', 'Blob', 'File']):
                file_operations = True
                suspicious_patterns.append({
                    "type": "file_operation",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查系统调用
        system_calls = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['eval', 'Function', 'setTimeout', 'setInterval']):
                system_calls = True
                suspicious_patterns.append({
                    "type": "system_call",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 更新内容对象
        content.text = source
        content.functions = functions
        content.suspicious_patterns = suspicious_patterns
        
        # 创建元数据对象
        metadata = ScriptMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="javascript",
            line_count=line_count,
            function_count=len(functions),
            class_count=0,
            import_count=0,
            has_suspicious_imports=False,
            has_suspicious_functions=any(f["name"] in ['eval', 'Function'] for f in functions),
            has_suspicious_strings=False,
            has_network_calls=network_calls,
            has_file_operations=file_operations,
            has_system_calls=system_calls
        )
        
        # 添加漏洞警告
        if network_calls:
            vulnerabilities.append("包含网络调用")
        if file_operations:
            vulnerabilities.append("包含文件操作")
        if system_calls:
            vulnerabilities.append("包含系统调用")
        
        return ScriptAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except Exception as e:
        return ScriptAnalysisResult(
            metadata=ScriptMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="javascript",
                line_count=0,
                function_count=0,
                class_count=0,
                import_count=0
            ),
            content=ScriptContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_vbs(file_path: str, file_size: int) -> ScriptAnalysisResult:
    """分析VBScript脚本"""
    content = ScriptContent()
    vulnerabilities = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        
        # 统计行数
        line_count = len(source.splitlines())
        
        # 提取函数定义
        functions = []
        for line in source.splitlines():
            if line.strip().startswith('Function ') or line.strip().startswith('Sub '):
                func_name = line.strip().split()[1].split('(')[0]
                functions.append({
                    "name": func_name,
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查可疑模式
        suspicious_patterns = []
        
        # 检查网络调用
        network_calls = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['MSXML2.XMLHTTP', 'WinHttp.WinHttpRequest', 'InternetExplorer.Application']):
                network_calls = True
                suspicious_patterns.append({
                    "type": "network_call",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查文件操作
        file_operations = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['FileSystemObject', 'CreateObject', 'OpenTextFile', 'WriteLine']):
                file_operations = True
                suspicious_patterns.append({
                    "type": "file_operation",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 检查系统调用
        system_calls = False
        for line in source.splitlines():
            if any(cmd in line for cmd in ['WScript.Shell', 'Shell.Application', 'CreateObject', 'Execute']):
                system_calls = True
                suspicious_patterns.append({
                    "type": "system_call",
                    "name": line.strip(),
                    "lineno": source.splitlines().index(line) + 1
                })
        
        # 更新内容对象
        content.text = source
        content.functions = functions
        content.suspicious_patterns = suspicious_patterns
        
        # 创建元数据对象
        metadata = ScriptMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="vbs",
            line_count=line_count,
            function_count=len(functions),
            class_count=0,
            import_count=0,
            has_suspicious_imports=False,
            has_suspicious_functions=any(f["name"] in ['Execute', 'Eval'] for f in functions),
            has_suspicious_strings=False,
            has_network_calls=network_calls,
            has_file_operations=file_operations,
            has_system_calls=system_calls
        )
        
        # 添加漏洞警告
        if network_calls:
            vulnerabilities.append("包含网络调用")
        if file_operations:
            vulnerabilities.append("包含文件操作")
        if system_calls:
            vulnerabilities.append("包含系统调用")
        
        return ScriptAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except Exception as e:
        return ScriptAnalysisResult(
            metadata=ScriptMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="vbs",
                line_count=0,
                function_count=0,
                class_count=0,
                import_count=0
            ),
            content=ScriptContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

class BinaryMetadata(BaseModel):
    """二进制文件元数据"""
    file_path: str
    file_size: int
    file_type: str  # exe, dll, so, dylib, bin
    architecture: Optional[str] = None  # x86, x64, arm, etc.
    entry_point: Optional[int] = None
    sections: List[Dict[str, Any]] = []
    imports: List[Dict[str, Any]] = []
    exports: List[Dict[str, Any]] = []
    has_signature: bool = False
    is_packed: bool = False
    is_encrypted: bool = False
    has_suspicious_imports: bool = False
    has_suspicious_exports: bool = False
    has_suspicious_sections: bool = False

class BinaryContent(BaseModel):
    """二进制文件内容"""
    hex_dump: str = ""
    strings: List[Dict[str, Any]] = []
    sections: List[Dict[str, Any]] = []
    imports: List[Dict[str, Any]] = []
    exports: List[Dict[str, Any]] = []
    suspicious_patterns: List[Dict[str, Any]] = []

class BinaryAnalysisResult(BaseModel):
    """二进制文件分析结果"""
    metadata: BinaryMetadata
    content: BinaryContent
    vulnerabilities: List[str] = []
    error_message: Optional[str] = None

async def analyze_binary(file_path: str, timeout: int = 60) -> BinaryAnalysisResult:
    """
    分析二进制文件
    
    Args:
        file_path: 二进制文件路径
        timeout: 分析超时时间（秒）
        
    Returns:
        BinaryAnalysisResult: 二进制文件分析结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return BinaryAnalysisResult(
                metadata=BinaryMetadata(
                    file_path=file_path,
                    file_size=0,
                    file_type="unknown"
                ),
                content=BinaryContent(),
                vulnerabilities=["文件不存在"],
                error_message="文件不存在"
            )

        # 获取文件信息
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # 根据文件类型选择不同的分析方法
        if file_ext in ['.exe', '.dll']:
            return await analyze_pe(file_path, file_size)
        elif file_ext in ['.so', '.dylib']:
            return await analyze_elf(file_path, file_size)
        else:
            return await analyze_raw_binary(file_path, file_size)
            
    except Exception as e:
        return BinaryAnalysisResult(
            metadata=BinaryMetadata(
                file_path=file_path,
                file_size=0,
                file_type="unknown"
            ),
            content=BinaryContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_pe(file_path: str, file_size: int) -> BinaryAnalysisResult:
    """分析PE文件（Windows可执行文件）"""
    import pefile
    
    content = BinaryContent()
    vulnerabilities = []
    
    try:
        # 打开PE文件
        pe = pefile.PE(file_path)
        
        # 提取基本信息
        architecture = "x64" if pe.OPTIONAL_HEADER.Magic == 0x20b else "x86"
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        # 提取节信息
        sections = []
        for section in pe.sections:
            sections.append({
                "name": section.Name.decode().rstrip('\x00'),
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "characteristics": section.Characteristics
            })
        
        # 提取导入信息
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imports.append({
                            "dll": entry.dll.decode(),
                            "name": imp.name.decode(),
                            "address": imp.address
                        })
        
        # 提取导出信息
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append({
                        "name": exp.name.decode(),
                        "address": exp.address,
                        "ordinal": exp.ordinal
                    })
        
        # 检查可疑特征
        suspicious_patterns = []
        
        # 检查可疑节
        suspicious_sections = False
        for section in sections:
            if section["name"] in [".text", ".data", ".rdata", ".rsrc"]:
                if section["characteristics"] & 0xE0000000:  # 可执行
                    suspicious_sections = True
                    suspicious_patterns.append({
                        "type": "suspicious_section",
                        "name": section["name"],
                        "characteristics": section["characteristics"]
                    })
        
        # 检查可疑导入
        suspicious_imports = False
        for imp in imports:
            if imp["dll"].lower() in ["kernel32.dll", "advapi32.dll", "ws2_32.dll"]:
                if imp["name"] in ["CreateRemoteThread", "WriteProcessMemory", "VirtualAlloc", "socket", "connect"]:
                    suspicious_imports = True
                    suspicious_patterns.append({
                        "type": "suspicious_import",
                        "dll": imp["dll"],
                        "name": imp["name"]
                    })
        
        # 检查可疑导出
        suspicious_exports = False
        for exp in exports:
            if exp["name"] in ["DllMain", "CreateRemoteThread", "WriteProcessMemory"]:
                suspicious_exports = True
                suspicious_patterns.append({
                    "type": "suspicious_export",
                    "name": exp["name"]
                })
        
        # 检查是否加壳
        is_packed = False
        if len(sections) > 0:
            # 检查节名和特征
            for section in sections:
                if section["name"] in ["UPX0", "UPX1", "ASPack"]:
                    is_packed = True
                    suspicious_patterns.append({
                        "type": "packed",
                        "name": section["name"]
                    })
                    break
        
        # 检查是否加密
        is_encrypted = False
        if len(sections) > 0:
            # 检查节的熵值
            for section in sections:
                if section["raw_size"] > 0:
                    with open(file_path, 'rb') as f:
                        f.seek(section.PointerToRawData)
                        data = f.read(section.SizeOfRawData)
                        entropy = calculate_entropy(data)
                        if entropy > 7.0:  # 高熵值通常表示加密或压缩
                            is_encrypted = True
                            suspicious_patterns.append({
                                "type": "encrypted",
                                "section": section["name"],
                                "entropy": entropy
                            })
        
        # 更新内容对象
        content.sections = sections
        content.imports = imports
        content.exports = exports
        content.suspicious_patterns = suspicious_patterns
        
        # 创建元数据对象
        metadata = BinaryMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="pe",
            architecture=architecture,
            entry_point=entry_point,
            sections=sections,
            imports=imports,
            exports=exports,
            has_signature=hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'),
            is_packed=is_packed,
            is_encrypted=is_encrypted,
            has_suspicious_imports=suspicious_imports,
            has_suspicious_exports=suspicious_exports,
            has_suspicious_sections=suspicious_sections
        )
        
        # 添加漏洞警告
        if suspicious_sections:
            vulnerabilities.append("包含可疑节")
        if suspicious_imports:
            vulnerabilities.append("包含可疑导入")
        if suspicious_exports:
            vulnerabilities.append("包含可疑导出")
        if is_packed:
            vulnerabilities.append("文件可能被加壳")
        if is_encrypted:
            vulnerabilities.append("文件可能被加密")
        
        return BinaryAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except pefile.PEFormatError:
        return BinaryAnalysisResult(
            metadata=BinaryMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="pe"
            ),
            content=BinaryContent(),
            vulnerabilities=["无效的PE文件"],
            error_message="无效的PE文件"
        )

async def analyze_elf(file_path: str, file_size: int) -> BinaryAnalysisResult:
    """分析ELF文件（Linux可执行文件）"""
    import elftools.elf.elffile
    
    content = BinaryContent()
    vulnerabilities = []
    
    try:
        # 打开ELF文件
        with open(file_path, 'rb') as f:
            elf = elftools.elf.elffile.ELFFile(f)
        
        # 提取基本信息
        architecture = elf.get_machine_arch()
        entry_point = elf.header.e_entry
        
        # 提取节信息
        sections = []
        for section in elf.iter_sections():
            sections.append({
                "name": section.name,
                "type": section['sh_type'],
                "flags": section['sh_flags'],
                "address": section['sh_addr'],
                "size": section['sh_size']
            })
        
        # 提取动态符号（导入）
        imports = []
        if elf.has_dynamic_symbols():
            for sym in elf.iter_dynamic_symbols():
                if sym.entry['st_info']['type'] == 'STT_FUNC':
                    imports.append({
                        "name": sym.name,
                        "address": sym.entry['st_value']
                    })
        
        # 提取符号表（导出）
        exports = []
        if elf.has_symbols():
            for sym in elf.iter_symbols():
                if sym.entry['st_info']['type'] == 'STT_FUNC':
                    exports.append({
                        "name": sym.name,
                        "address": sym.entry['st_value']
                    })
        
        # 检查可疑特征
        suspicious_patterns = []
        
        # 检查可疑节
        suspicious_sections = False
        for section in sections:
            if section["name"] in [".text", ".data", ".rodata"]:
                if section["flags"] & 0x7:  # 可执行
                    suspicious_sections = True
                    suspicious_patterns.append({
                        "type": "suspicious_section",
                        "name": section["name"],
                        "flags": section["flags"]
                    })
        
        # 检查可疑导入
        suspicious_imports = False
        for imp in imports:
            if imp["name"] in ["execve", "system", "popen", "socket", "connect"]:
                suspicious_imports = True
                suspicious_patterns.append({
                    "type": "suspicious_import",
                    "name": imp["name"]
                })
        
        # 检查可疑导出
        suspicious_exports = False
        for exp in exports:
            if exp["name"] in ["main", "init", "fini"]:
                suspicious_exports = True
                suspicious_patterns.append({
                    "type": "suspicious_export",
                    "name": exp["name"]
                })
        
        # 检查是否加壳
        is_packed = False
        if len(sections) > 0:
            # 检查节名和特征
            for section in sections:
                if section["name"] in ["UPX0", "UPX1", "ASPack"]:
                    is_packed = True
                    suspicious_patterns.append({
                        "type": "packed",
                        "name": section["name"]
                    })
                    break
        
        # 检查是否加密
        is_encrypted = False
        if len(sections) > 0:
            # 检查节的熵值
            for section in sections:
                if section["size"] > 0:
                    with open(file_path, 'rb') as f:
                        f.seek(section["address"])
                        data = f.read(section["size"])
                        entropy = calculate_entropy(data)
                        if entropy > 7.0:  # 高熵值通常表示加密或压缩
                            is_encrypted = True
                            suspicious_patterns.append({
                                "type": "encrypted",
                                "section": section["name"],
                                "entropy": entropy
                            })
        
        # 更新内容对象
        content.sections = sections
        content.imports = imports
        content.exports = exports
        content.suspicious_patterns = suspicious_patterns
        
        # 创建元数据对象
        metadata = BinaryMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="elf",
            architecture=architecture,
            entry_point=entry_point,
            sections=sections,
            imports=imports,
            exports=exports,
            has_signature=False,  # ELF文件通常没有数字签名
            is_packed=is_packed,
            is_encrypted=is_encrypted,
            has_suspicious_imports=suspicious_imports,
            has_suspicious_exports=suspicious_exports,
            has_suspicious_sections=suspicious_sections
        )
        
        # 添加漏洞警告
        if suspicious_sections:
            vulnerabilities.append("包含可疑节")
        if suspicious_imports:
            vulnerabilities.append("包含可疑导入")
        if suspicious_exports:
            vulnerabilities.append("包含可疑导出")
        if is_packed:
            vulnerabilities.append("文件可能被加壳")
        if is_encrypted:
            vulnerabilities.append("文件可能被加密")
        
        return BinaryAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except Exception as e:
        return BinaryAnalysisResult(
            metadata=BinaryMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="elf"
            ),
            content=BinaryContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_raw_binary(file_path: str, file_size: int) -> BinaryAnalysisResult:
    """分析原始二进制文件"""
    content = BinaryContent()
    vulnerabilities = []
    
    try:
        # 读取文件内容
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # 生成十六进制转储
        hex_dump = data.hex()
        
        # 提取字符串
        strings = []
        current_string = ""
        for byte in data:
            if 32 <= byte <= 126:  # 可打印ASCII字符
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:  # 只保留长度大于等于4的字符串
                    strings.append({
                        "value": current_string,
                        "offset": data.index(current_string.encode())
                    })
                current_string = ""
        
        # 检查可疑特征
        suspicious_patterns = []
        
        # 检查是否加密
        is_encrypted = False
        entropy = calculate_entropy(data)
        if entropy > 7.0:  # 高熵值通常表示加密或压缩
            is_encrypted = True
            suspicious_patterns.append({
                "type": "encrypted",
                "entropy": entropy
            })
        
        # 更新内容对象
        content.hex_dump = hex_dump
        content.strings = strings
        content.suspicious_patterns = suspicious_patterns
        
        # 创建元数据对象
        metadata = BinaryMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="bin",
            is_encrypted=is_encrypted
        )
        
        # 添加漏洞警告
        if is_encrypted:
            vulnerabilities.append("文件可能被加密")
        
        return BinaryAnalysisResult(
            metadata=metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except Exception as e:
        return BinaryAnalysisResult(
            metadata=BinaryMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="bin"
            ),
            content=BinaryContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

def calculate_entropy(data: bytes) -> float:
    """计算数据的熵值"""
    if not data:
        return 0.0
    
    # 计算每个字节的频率
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # 计算熵值
    entropy = 0.0
    for count in freq.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    
    return entropy

class ImageMetadata(BaseModel):
    """图片文件元数据"""
    file_path: str
    file_size: int
    file_type: str  # jpeg, png, gif, bmp, etc.
    width: int
    height: int
    format: str
    mode: str  # RGB, RGBA, CMYK, etc.
    dpi: Optional[tuple[int, int]] = None
    has_exif: bool = False
    has_icc: bool = False
    has_alpha: bool = False
    has_animation: bool = False
    has_transparency: bool = False
    has_embedded_files: bool = False
    has_suspicious_metadata: bool = False
    has_suspicious_content: bool = False

class ImageContent(BaseModel):
    """图片文件内容"""
    exif_data: Dict[str, Any] = {}
    icc_profile: Dict[str, Any] = {}
    embedded_files: List[Dict[str, Any]] = []
    color_palette: List[Dict[str, Any]] = []
    suspicious_patterns: List[Dict[str, Any]] = []

class ImageAnalysisResult(BaseModel):
    """图片文件分析结果"""
    metadata: ImageMetadata
    content: ImageContent
    vulnerabilities: List[str] = []
    error_message: Optional[str] = None

async def analyze_image(file_path: str, timeout: int = 60) -> ImageAnalysisResult:
    """
    分析图片文件
    
    Args:
        file_path: 图片文件路径
        timeout: 分析超时时间（秒）
        
    Returns:
        ImageAnalysisResult: 图片文件分析结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return ImageAnalysisResult(
                metadata=ImageMetadata(
                    file_path=file_path,
                    file_size=0,
                    file_type="unknown",
                    width=0,
                    height=0,
                    format="unknown",
                    mode="unknown"
                ),
                content=ImageContent(),
                vulnerabilities=["文件不存在"],
                error_message="文件不存在"
            )

        # 获取文件信息
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # 根据文件类型选择不同的分析方法
        if file_ext in ['.jpg', '.jpeg']:
            return await analyze_jpeg(file_path, file_size)
        elif file_ext == '.png':
            return await analyze_png(file_path, file_size)
        elif file_ext == '.gif':
            return await analyze_gif(file_path, file_size)
        elif file_ext == '.bmp':
            return await analyze_bmp(file_path, file_size)
        else:
            return ImageAnalysisResult(
                metadata=ImageMetadata(
                    file_path=file_path,
                    file_size=file_size,
                    file_type="unknown",
                    width=0,
                    height=0,
                    format="unknown",
                    mode="unknown"
                ),
                content=ImageContent(),
                vulnerabilities=["不支持的文件类型"],
                error_message=f"不支持的文件类型: {file_ext}"
            )
            
    except Exception as e:
        return ImageAnalysisResult(
            metadata=ImageMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="unknown",
                width=0,
                height=0,
                format="unknown",
                mode="unknown"
            ),
            content=ImageContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_jpeg(file_path: str, file_size: int) -> ImageAnalysisResult:
    """分析JPEG文件"""
    import piexif
    import piexif.helper
    
    content = ImageContent()
    vulnerabilities = []
    
    try:
        # 打开图片
        with Image.open(file_path) as img:
            # 提取基本信息
            width, height = img.size
            format = img.format
            mode = img.mode
            
            # 提取DPI信息
            dpi = img.info.get('dpi')
            
            # 提取EXIF数据
            exif_data = {}
            has_exif = False
            if hasattr(img, '_getexif') and img._getexif():
                exif = img._getexif()
                for tag_id in exif:
                    tag = TAGS.get(tag_id, tag_id)
                    data = exif.get(tag_id)
                    if isinstance(data, bytes):
                        data = data.decode(errors='replace')
                    exif_data[tag] = data
                has_exif = True
            
            # 提取ICC配置文件
            icc_profile = {}
            has_icc = False
            if 'icc_profile' in img.info:
                icc_profile = img.info['icc_profile']
                has_icc = True
            
            # 检查透明度
            has_alpha = 'A' in mode
            has_transparency = img.info.get('transparency') is not None
            
            # 检查嵌入文件
            embedded_files = []
            has_embedded_files = False
            if 'exif' in img.info:
                try:
                    exif_dict = piexif.load(img.info['exif'])
                    if '1st' in exif_dict and 'MakerNote' in exif_dict['1st']:
                        has_embedded_files = True
                        embedded_files.append({
                            "type": "maker_note",
                            "size": len(exif_dict['1st']['MakerNote'])
                        })
                except:
                    pass
            
            # 提取颜色调色板
            color_palette = []
            if img.mode == 'P':
                palette = img.getpalette()
                if palette:
                    for i in range(0, len(palette), 3):
                        color_palette.append({
                            "rgb": tuple(palette[i:i+3])
                        })
            
            # 检查可疑特征
            suspicious_patterns = []
            
            # 检查可疑元数据
            suspicious_metadata = False
            if has_exif:
                suspicious_tags = [
                    'Software', 'Make', 'Model', 'DateTime',
                    'GPSInfo', 'UserComment', 'XPComment'
                ]
                for tag in suspicious_tags:
                    if tag in exif_data:
                        suspicious_metadata = True
                        suspicious_patterns.append({
                            "type": "suspicious_metadata",
                            "tag": tag,
                            "value": exif_data[tag]
                        })
            
            # 检查可疑内容
            suspicious_content = False
            # 检查图片尺寸是否异常
            if width > 10000 or height > 10000:
                suspicious_content = True
                suspicious_patterns.append({
                    "type": "suspicious_size",
                    "width": width,
                    "height": height
                })
            
            # 更新内容对象
            content.exif_data = exif_data
            content.icc_profile = icc_profile
            content.embedded_files = embedded_files
            content.color_palette = color_palette
            content.suspicious_patterns = suspicious_patterns
            
            # 创建元数据对象
            metadata = ImageMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="jpeg",
                width=width,
                height=height,
                format=format,
                mode=mode,
                dpi=dpi,
                has_exif=has_exif,
                has_icc=has_icc,
                has_alpha=has_alpha,
                has_animation=False,
                has_transparency=has_transparency,
                has_embedded_files=has_embedded_files,
                has_suspicious_metadata=suspicious_metadata,
                has_suspicious_content=suspicious_content
            )
            
            # 添加漏洞警告
            if suspicious_metadata:
                vulnerabilities.append("包含可疑的元数据")
            if suspicious_content:
                vulnerabilities.append("包含可疑的内容")
            if has_embedded_files:
                vulnerabilities.append("包含嵌入文件")
            
            return ImageAnalysisResult(
                metadata=metadata,
                content=content,
                vulnerabilities=vulnerabilities
            )
            
    except Exception as e:
        return ImageAnalysisResult(
            metadata=ImageMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="jpeg",
                width=0,
                height=0,
                format="unknown",
                mode="unknown"
            ),
            content=ImageContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_png(file_path: str, file_size: int) -> ImageAnalysisResult:
    """分析PNG文件"""
    import png
    
    content = ImageContent()
    vulnerabilities = []
    
    try:
        # 打开图片
        with Image.open(file_path) as img:
            # 提取基本信息
            width, height = img.size
            format = img.format
            mode = img.mode
            
            # 提取DPI信息
            dpi = img.info.get('dpi')
            
            # 检查透明度
            has_alpha = 'A' in mode
            has_transparency = img.info.get('transparency') is not None
            
            # 提取嵌入文件
            embedded_files = []
            has_embedded_files = False
            if 'chunks' in img.info:
                for chunk in img.info['chunks']:
                    if chunk[0] in ['tEXt', 'zTXt', 'iTXt']:
                        has_embedded_files = True
                        embedded_files.append({
                            "type": chunk[0],
                            "size": len(chunk[1])
                        })
            
            # 提取颜色调色板
            color_palette = []
            if img.mode == 'P':
                palette = img.getpalette()
                if palette:
                    for i in range(0, len(palette), 3):
                        color_palette.append({
                            "rgb": tuple(palette[i:i+3])
                        })
            
            # 检查可疑特征
            suspicious_patterns = []
            
            # 检查可疑内容
            suspicious_content = False
            # 检查图片尺寸是否异常
            if width > 10000 or height > 10000:
                suspicious_content = True
                suspicious_patterns.append({
                    "type": "suspicious_size",
                    "width": width,
                    "height": height
                })
            
            # 更新内容对象
            content.embedded_files = embedded_files
            content.color_palette = color_palette
            content.suspicious_patterns = suspicious_patterns
            
            # 创建元数据对象
            metadata = ImageMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="png",
                width=width,
                height=height,
                format=format,
                mode=mode,
                dpi=dpi,
                has_exif=False,
                has_icc=False,
                has_alpha=has_alpha,
                has_animation=False,
                has_transparency=has_transparency,
                has_embedded_files=has_embedded_files,
                has_suspicious_metadata=False,
                has_suspicious_content=suspicious_content
            )
            
            # 添加漏洞警告
            if suspicious_content:
                vulnerabilities.append("包含可疑的内容")
            if has_embedded_files:
                vulnerabilities.append("包含嵌入文件")
            
            return ImageAnalysisResult(
                metadata=metadata,
                content=content,
                vulnerabilities=vulnerabilities
            )
            
    except Exception as e:
        return ImageAnalysisResult(
            metadata=ImageMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="png",
                width=0,
                height=0,
                format="unknown",
                mode="unknown"
            ),
            content=ImageContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_gif(file_path: str, file_size: int) -> ImageAnalysisResult:
    """分析GIF文件"""
    from PIL import Image
    
    content = ImageContent()
    vulnerabilities = []
    
    try:
        # 打开图片
        with Image.open(file_path) as img:
            # 提取基本信息
            width, height = img.size
            format = img.format
            mode = img.mode
            
            # 检查动画
            has_animation = getattr(img, "is_animated", False)
            frame_count = getattr(img, "n_frames", 1)
            
            # 检查透明度
            has_alpha = 'A' in mode
            has_transparency = img.info.get('transparency') is not None
            
            # 提取颜色调色板
            color_palette = []
            if img.mode == 'P':
                palette = img.getpalette()
                if palette:
                    for i in range(0, len(palette), 3):
                        color_palette.append({
                            "rgb": tuple(palette[i:i+3])
                        })
            
            # 检查可疑特征
            suspicious_patterns = []
            
            # 检查可疑内容
            suspicious_content = False
            # 检查图片尺寸是否异常
            if width > 10000 or height > 10000:
                suspicious_content = True
                suspicious_patterns.append({
                    "type": "suspicious_size",
                    "width": width,
                    "height": height
                })
            
            # 检查帧数是否异常
            if frame_count > 100:
                suspicious_content = True
                suspicious_patterns.append({
                    "type": "suspicious_frames",
                    "count": frame_count
                })
            
            # 更新内容对象
            content.color_palette = color_palette
            content.suspicious_patterns = suspicious_patterns
            
            # 创建元数据对象
            metadata = ImageMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="gif",
                width=width,
                height=height,
                format=format,
                mode=mode,
                has_exif=False,
                has_icc=False,
                has_alpha=has_alpha,
                has_animation=has_animation,
                has_transparency=has_transparency,
                has_embedded_files=False,
                has_suspicious_metadata=False,
                has_suspicious_content=suspicious_content
            )
            
            # 添加漏洞警告
            if suspicious_content:
                vulnerabilities.append("包含可疑的内容")
            if has_animation and frame_count > 100:
                vulnerabilities.append("包含过多的动画帧")
            
            return ImageAnalysisResult(
                metadata=metadata,
                content=content,
                vulnerabilities=vulnerabilities
            )
            
    except Exception as e:
        return ImageAnalysisResult(
            metadata=ImageMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="gif",
                width=0,
                height=0,
                format="unknown",
                mode="unknown"
            ),
            content=ImageContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_bmp(file_path: str, file_size: int) -> ImageAnalysisResult:
    """分析BMP文件"""
    from PIL import Image
    
    content = ImageContent()
    vulnerabilities = []
    
    try:
        # 打开图片
        with Image.open(file_path) as img:
            # 提取基本信息
            width, height = img.size
            format = img.format
            mode = img.mode
            
            # 检查透明度
            has_alpha = 'A' in mode
            has_transparency = img.info.get('transparency') is not None
            
            # 提取颜色调色板
            color_palette = []
            if img.mode == 'P':
                palette = img.getpalette()
                if palette:
                    for i in range(0, len(palette), 3):
                        color_palette.append({
                            "rgb": tuple(palette[i:i+3])
                        })
            
            # 检查可疑特征
            suspicious_patterns = []
            
            # 检查可疑内容
            suspicious_content = False
            # 检查图片尺寸是否异常
            if width > 10000 or height > 10000:
                suspicious_content = True
                suspicious_patterns.append({
                    "type": "suspicious_size",
                    "width": width,
                    "height": height
                })
            
            # 更新内容对象
            content.color_palette = color_palette
            content.suspicious_patterns = suspicious_patterns
            
            # 创建元数据对象
            metadata = ImageMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="bmp",
                width=width,
                height=height,
                format=format,
                mode=mode,
                has_exif=False,
                has_icc=False,
                has_alpha=has_alpha,
                has_animation=False,
                has_transparency=has_transparency,
                has_embedded_files=False,
                has_suspicious_metadata=False,
                has_suspicious_content=suspicious_content
            )
            
            # 添加漏洞警告
            if suspicious_content:
                vulnerabilities.append("包含可疑的内容")
            
            return ImageAnalysisResult(
                metadata=metadata,
                content=content,
                vulnerabilities=vulnerabilities
            )
            
    except Exception as e:
        return ImageAnalysisResult(
            metadata=ImageMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="bmp",
                width=0,
                height=0,
                format="unknown",
                mode="unknown"
            ),
            content=ImageContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

class MediaMetadata(BaseModel):
    """媒体文件元数据"""
    file_path: str
    file_size: int
    file_type: str  # audio, video
    format: str  # mp3, wav, mp4, avi, etc.
    duration: Optional[float] = None  # 时长（秒）
    bitrate: Optional[int] = None  # 比特率
    sample_rate: Optional[int] = None  # 采样率（音频）
    channels: Optional[int] = None  # 声道数（音频）
    width: Optional[int] = None  # 视频宽度
    height: Optional[int] = None  # 视频高度
    fps: Optional[float] = None  # 帧率（视频）
    codec: Optional[str] = None  # 编解码器
    has_metadata: bool = False  # 是否包含元数据
    has_cover: bool = False  # 是否包含封面
    has_subtitles: bool = False  # 是否包含字幕
    has_chapters: bool = False  # 是否包含章节
    has_watermark: bool = False  # 是否包含水印
    has_suspicious_metadata: bool = False  # 是否包含可疑元数据
    has_suspicious_content: bool = False  # 是否包含可疑内容

class MediaContent(BaseModel):
    """媒体文件内容"""
    metadata: Dict[str, Any] = {}  # 元数据
    cover: Optional[Dict[str, Any]] = None  # 封面信息
    subtitles: List[Dict[str, Any]] = []  # 字幕信息
    chapters: List[Dict[str, Any]] = []  # 章节信息
    suspicious_patterns: List[Dict[str, Any]] = []  # 可疑特征

class MediaAnalysisResult(BaseModel):
    """媒体文件分析结果"""
    metadata: MediaMetadata
    content: MediaContent
    vulnerabilities: List[str] = []
    error_message: Optional[str] = None

async def analyze_media(file_path: str, timeout: int = 60) -> MediaAnalysisResult:
    """
    分析媒体文件
    
    Args:
        file_path: 媒体文件路径
        timeout: 分析超时时间（秒）
        
    Returns:
        MediaAnalysisResult: 媒体文件分析结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return MediaAnalysisResult(
                metadata=MediaMetadata(
                    file_path=file_path,
                    file_size=0,
                    file_type="unknown",
                    format="unknown"
                ),
                content=MediaContent(),
                vulnerabilities=["文件不存在"],
                error_message="文件不存在"
            )

        # 获取文件信息
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # 根据文件类型选择不同的分析方法
        if file_ext in ['.mp3', '.wav', '.flac', '.aac', '.ogg']:
            return await analyze_audio(file_path, file_size)
        elif file_ext in ['.mp4', '.avi', '.mkv', '.mov', '.wmv']:
            return await analyze_video(file_path, file_size)
        else:
            return MediaAnalysisResult(
                metadata=MediaMetadata(
                    file_path=file_path,
                    file_size=file_size,
                    file_type="unknown",
                    format="unknown"
                ),
                content=MediaContent(),
                vulnerabilities=["不支持的文件类型"],
                error_message=f"不支持的文件类型: {file_ext}"
            )
            
    except Exception as e:
        return MediaAnalysisResult(
            metadata=MediaMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="unknown",
                format="unknown"
            ),
            content=MediaContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_audio(file_path: str, file_size: int) -> MediaAnalysisResult:
    """分析音频文件"""
    from mutagen import File
    from mutagen.id3 import ID3
    from mutagen.flac import FLAC
    from mutagen.mp3 import MP3
    from mutagen.oggvorbis import OggVorbis
    from mutagen.aac import AAC
    
    content = MediaContent()
    vulnerabilities = []
    
    try:
        # 打开音频文件
        audio = File(file_path)
        if audio is None:
            return MediaAnalysisResult(
                metadata=MediaMetadata(
                    file_path=file_path,
                    file_size=file_size,
                    file_type="audio",
                    format="unknown"
                ),
                content=MediaContent(),
                vulnerabilities=["无法解析音频文件"],
                error_message="无法解析音频文件"
            )
        
        # 提取基本信息
        format = audio.mime[0].split('/')[-1] if audio.mime else "unknown"
        duration = audio.info.length if hasattr(audio.info, 'length') else None
        bitrate = audio.info.bitrate if hasattr(audio.info, 'bitrate') else None
        sample_rate = audio.info.sample_rate if hasattr(audio.info, 'sample_rate') else None
        channels = audio.info.channels if hasattr(audio.info, 'channels') else None
        
        # 提取元数据
        metadata = {}
        has_metadata = False
        has_cover = False
        cover = None
        
        if isinstance(audio, ID3):
            # MP3文件
            for key in audio.keys():
                if key.startswith('T'):
                    metadata[key] = str(audio[key])
                elif key == 'APIC':
                    has_cover = True
                    cover = {
                        "type": audio[key].mime,
                        "size": len(audio[key].data)
                    }
            has_metadata = True
        elif isinstance(audio, FLAC):
            # FLAC文件
            for key, value in audio.tags.items():
                metadata[key] = str(value)
            if audio.pictures:
                has_cover = True
                cover = {
                    "type": audio.pictures[0].mime,
                    "size": len(audio.pictures[0].data)
                }
            has_metadata = True
        elif isinstance(audio, OggVorbis):
            # OGG文件
            for key, value in audio.tags.items():
                metadata[key] = str(value)
            has_metadata = True
        
        # 检查可疑特征
        suspicious_patterns = []
        
        # 检查可疑元数据
        suspicious_metadata = False
        if has_metadata:
            suspicious_tags = [
                'TXXX', 'WXXX', 'COMM', 'USLT', 'SYLT',
                'PRIV', 'APIC', 'GEOB', 'AENC'
            ]
            for tag in suspicious_tags:
                if tag in metadata:
                    suspicious_metadata = True
                    suspicious_patterns.append({
                        "type": "suspicious_metadata",
                        "tag": tag,
                        "value": metadata[tag]
                    })
        
        # 检查可疑内容
        suspicious_content = False
        # 检查文件大小是否异常
        if file_size > 100 * 1024 * 1024:  # 大于100MB
            suspicious_content = True
            suspicious_patterns.append({
                "type": "suspicious_size",
                "size": file_size
            })
        
        # 检查比特率是否异常
        if bitrate and bitrate > 320000:  # 大于320kbps
            suspicious_content = True
            suspicious_patterns.append({
                "type": "suspicious_bitrate",
                "bitrate": bitrate
            })
        
        # 更新内容对象
        content.metadata = metadata
        content.cover = cover
        content.suspicious_patterns = suspicious_patterns
        
        # 创建元数据对象
        media_metadata = MediaMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="audio",
            format=format,
            duration=duration,
            bitrate=bitrate,
            sample_rate=sample_rate,
            channels=channels,
            has_metadata=has_metadata,
            has_cover=has_cover,
            has_subtitles=False,
            has_chapters=False,
            has_watermark=False,
            has_suspicious_metadata=suspicious_metadata,
            has_suspicious_content=suspicious_content
        )
        
        # 添加漏洞警告
        if suspicious_metadata:
            vulnerabilities.append("包含可疑的元数据")
        if suspicious_content:
            vulnerabilities.append("包含可疑的内容")
        if has_cover:
            vulnerabilities.append("包含封面图片")
        
        return MediaAnalysisResult(
            metadata=media_metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except Exception as e:
        return MediaAnalysisResult(
            metadata=MediaMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="audio",
                format="unknown"
            ),
            content=MediaContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )

async def analyze_video(file_path: str, file_size: int) -> MediaAnalysisResult:
    """分析视频文件"""
    import cv2
    from moviepy.editor import VideoFileClip
    from mutagen import File
    from mutagen.mp4 import MP4
    from mutagen.matroska import Matroska
    
    content = MediaContent()
    vulnerabilities = []
    
    try:
        # 打开视频文件
        video = cv2.VideoCapture(file_path)
        if not video.isOpened():
            return MediaAnalysisResult(
                metadata=MediaMetadata(
                    file_path=file_path,
                    file_size=file_size,
                    file_type="video",
                    format="unknown"
                ),
                content=MediaContent(),
                vulnerabilities=["无法打开视频文件"],
                error_message="无法打开视频文件"
            )
        
        # 提取基本信息
        width = int(video.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(video.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = video.get(cv2.CAP_PROP_FPS)
        frame_count = int(video.get(cv2.CAP_PROP_FRAME_COUNT))
        duration = frame_count / fps if fps > 0 else None
        
        # 获取文件格式
        file_ext = os.path.splitext(file_path)[1].lower()
        format = file_ext[1:] if file_ext.startswith('.') else file_ext
        
        # 提取元数据
        metadata = {}
        has_metadata = False
        has_subtitles = False
        has_chapters = False
        subtitles = []
        chapters = []
        
        # 使用moviepy获取更多信息
        with VideoFileClip(file_path) as clip:
            bitrate = clip.reader.bitrate if hasattr(clip.reader, 'bitrate') else None
            audio = clip.audio
            if audio:
                sample_rate = audio.fps
                channels = audio.nchannels
            else:
                sample_rate = None
                channels = None
        
        # 检查字幕和章节
        if format in ['mp4', 'mkv']:
            media = File(file_path)
            if isinstance(media, MP4):
                # MP4文件
                if '©nam' in media:
                    metadata['title'] = str(media['©nam'][0])
                if '©art' in media:
                    metadata['artist'] = str(media['©art'][0])
                if '©alb' in media:
                    metadata['album'] = str(media['©alb'][0])
                if '©gen' in media:
                    metadata['genre'] = str(media['©gen'][0])
                if '©day' in media:
                    metadata['date'] = str(media['©day'][0])
                has_metadata = True
            elif isinstance(media, Matroska):
                # MKV文件
                if media.tags:
                    for tag in media.tags:
                        metadata[str(tag)] = str(media.tags[tag])
                if media.tracks:
                    for track in media.tracks:
                        if track.type == 'subtitles':
                            has_subtitles = True
                            subtitles.append({
                                "language": track.language,
                                "codec": track.codec
                            })
                has_metadata = True
        
        # 检查水印
        has_watermark = False
        # 检查前10帧
        for i in range(min(10, frame_count)):
            ret, frame = video.read()
            if ret:
                # 转换为灰度图
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                # 使用Canny边缘检测
                edges = cv2.Canny(gray, 100, 200)
                # 如果边缘数量异常，可能包含水印
                if cv2.countNonZero(edges) > width * height * 0.1:
                    has_watermark = True
                    break
        
        # 检查可疑特征
        suspicious_patterns = []
        
        # 检查可疑元数据
        suspicious_metadata = False
        if has_metadata:
            suspicious_tags = [
                'encoder', 'creation_time', 'modification_time',
                'handler_type', 'handler_name', 'handler_info'
            ]
            for tag in suspicious_tags:
                if tag in metadata:
                    suspicious_metadata = True
                    suspicious_patterns.append({
                        "type": "suspicious_metadata",
                        "tag": tag,
                        "value": metadata[tag]
                    })
        
        # 检查可疑内容
        suspicious_content = False
        # 检查文件大小是否异常
        if file_size > 1024 * 1024 * 1024:  # 大于1GB
            suspicious_content = True
            suspicious_patterns.append({
                "type": "suspicious_size",
                "size": file_size
            })
        
        # 检查分辨率是否异常
        if width > 3840 or height > 2160:  # 大于4K
            suspicious_content = True
            suspicious_patterns.append({
                "type": "suspicious_resolution",
                "width": width,
                "height": height
            })
        
        # 检查帧率是否异常
        if fps and fps > 60:  # 大于60fps
            suspicious_content = True
            suspicious_patterns.append({
                "type": "suspicious_fps",
                "fps": fps
            })
        
        # 更新内容对象
        content.metadata = metadata
        content.subtitles = subtitles
        content.chapters = chapters
        content.suspicious_patterns = suspicious_patterns
        
        # 创建元数据对象
        media_metadata = MediaMetadata(
            file_path=file_path,
            file_size=file_size,
            file_type="video",
            format=format,
            duration=duration,
            bitrate=bitrate,
            sample_rate=sample_rate,
            channels=channels,
            width=width,
            height=height,
            fps=fps,
            has_metadata=has_metadata,
            has_cover=False,
            has_subtitles=has_subtitles,
            has_chapters=has_chapters,
            has_watermark=has_watermark,
            has_suspicious_metadata=suspicious_metadata,
            has_suspicious_content=suspicious_content
        )
        
        # 添加漏洞警告
        if suspicious_metadata:
            vulnerabilities.append("包含可疑的元数据")
        if suspicious_content:
            vulnerabilities.append("包含可疑的内容")
        if has_subtitles:
            vulnerabilities.append("包含字幕")
        if has_watermark:
            vulnerabilities.append("包含水印")
        
        # 释放资源
        video.release()
        
        return MediaAnalysisResult(
            metadata=media_metadata,
            content=content,
            vulnerabilities=vulnerabilities
        )
        
    except Exception as e:
        return MediaAnalysisResult(
            metadata=MediaMetadata(
                file_path=file_path,
                file_size=file_size,
                file_type="video",
                format="unknown"
            ),
            content=MediaContent(),
            vulnerabilities=["分析失败"],
            error_message=str(e)
        )