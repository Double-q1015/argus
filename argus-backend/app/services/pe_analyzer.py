#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os
import tempfile
from typing import Dict, Any, Optional
from app.core.storage import get_sample

logger = logging.getLogger(__name__)

async def analyze_pe_file(file_path: str) -> Dict[str, Any]:
    """
    分析PE文件
    
    Args:
        file_path: 文件路径
        
    Returns:
        Dict[str, Any]: 分析结果
    """
    try:
        # 获取文件内容
        file_content = await get_sample(file_path)
        if not file_content:
            logger.error(f"Failed to get file content: {file_path}")
            return {"error": "Failed to get file content"}
        
        # 创建临时文件
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(file_content)
            temp_file_path = temp_file.name
        
        try:
            # 使用pefile库分析PE文件
            import pefile
            pe = pefile.PE(temp_file_path)
            
            # 提取基本信息
            result = {
                "machine": hex(pe.FILE_HEADER.Machine),
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "characteristics": hex(pe.FILE_HEADER.Characteristics),
                "optional_header": {
                    "magic": hex(pe.OPTIONAL_HEADER.Magic),
                    "linker_version": f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}",
                    "os_version": f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}",
                    "subsystem": hex(pe.OPTIONAL_HEADER.Subsystem),
                    "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
                    "size_of_stack_reserve": hex(pe.OPTIONAL_HEADER.SizeOfStackReserve),
                    "size_of_stack_commit": hex(pe.OPTIONAL_HEADER.SizeOfStackCommit),
                    "size_of_heap_reserve": hex(pe.OPTIONAL_HEADER.SizeOfHeapReserve),
                    "size_of_heap_commit": hex(pe.OPTIONAL_HEADER.SizeOfHeapCommit),
                    "number_of_rva_and_sizes": pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
                },
                "sections": []
            }
            
            # 提取节信息
            for section in pe.sections:
                result["sections"].append({
                    "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": hex(section.Misc_VirtualSize),
                    "raw_size": hex(section.SizeOfRawData),
                    "raw_address": hex(section.PointerToRawData),
                    "characteristics": hex(section.Characteristics)
                })
            
            # 提取导入表信息
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                result["imports"] = []
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    import_info = {
                        "dll": entry.dll.decode('utf-8', errors='ignore'),
                        "functions": []
                    }
                    for imp in entry.imports:
                        if imp.name:
                            import_info["functions"].append(imp.name.decode('utf-8', errors='ignore'))
                        else:
                            import_info["functions"].append(f"Ordinal: {imp.ordinal}")
                    result["imports"].append(import_info)
            
            # 提取导出表信息
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                result["exports"] = []
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        result["exports"].append(exp.name.decode('utf-8', errors='ignore'))
                    else:
                        result["exports"].append(f"Ordinal: {exp.ordinal}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing PE file: {e}")
            return {"error": str(e)}
            
        finally:
            # 删除临时文件
            try:
                os.unlink(temp_file_path)
            except Exception as e:
                logger.error(f"Error deleting temporary file: {e}")
                
    except Exception as e:
        logger.error(f"Error in analyze_pe_file: {e}")
        return {"error": str(e)} 