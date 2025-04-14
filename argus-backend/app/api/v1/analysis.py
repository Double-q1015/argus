from typing import List
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, status
from app.core.security import get_current_user
from app.models.user import User
from app.core.storage import upload_sample, storage
from app.core.analysis import analyze_sample
from app.models.sample import Sample
from app.core.exiftool_analyzer import perform_exiftool_analysis
import asyncio
import os
import tempfile

router = APIRouter()

@router.post("/files")
async def analyze_files(
    files: List[UploadFile] = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    上传并分析多个文件
    
    - 限制最多10个文件
    - 每个文件最大10MB
    """
    # 检查文件数量
    if len(files) > 10:
        raise HTTPException(status_code=400, detail="最多只能上传10个文件")
    
    # 检查文件大小
    MAX_SIZE = 10 * 1024 * 1024  # 10MB
    for file in files:
        content = await file.read()
        if len(content) > MAX_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"文件 {file.filename} 超过大小限制(10MB)"
            )
        await file.seek(0)  # 重置文件指针
    
    results = []
    for file in files:
        try:
            # 读取文件内容
            content = await file.read()
            
            # 上传文件到存储
            file_id = await upload_sample(content, file.filename, file.content_type)
            
            # 开始分析
            analysis_result = await analyze_sample(file_id)
            
            results.append({
                "filename": file.filename,
                "file_id": file_id,
                "status": "success",
                "result": analysis_result
            })
            
        except Exception as e:
            results.append({
                "filename": file.filename,
                "status": "error",
                "error": str(e)
            })
    
    return {
        "message": "文件分析完成",
        "results": results
    }

@router.post("/{sha256_digest}/analyze")
async def analyze_sample(
    sha256_digest: str,
    current_user: User = Depends(get_current_user)
):
    """
    分析样本文件
    """
    # 获取样本信息
    sample = await Sample.find_one({"sha256_digest": sha256_digest})
    if not sample:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample not found"
        )
    
    # 更新分析状态
    sample.analysis_status = "analyzing"
    await sample.save()
    
    try:
        # 创建临时文件
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            # 从存储中获取文件内容
            file_content = await storage.get_file(sample.file_path)
            if not file_content:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="File not found in storage"
                )
            
            # 写入临时文件
            temp_file.write(file_content.read())
            temp_file.flush()
            
            # 执行 exiftool 分析
            exiftool_results = await perform_exiftool_analysis(temp_file.name)
            
            # 更新样本分析结果
            sample.analysis_results = {
                "exiftool": exiftool_results
            }
            sample.analysis_status = "completed"
            await sample.save()
            
            return {
                "status": "success",
                "message": "Analysis completed",
                "results": sample.analysis_results
            }
            
    except Exception as e:
        # 更新分析状态为失败
        sample.analysis_status = "failed"
        await sample.save()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )
    finally:
        # 清理临时文件
        if 'temp_file' in locals():
            os.unlink(temp_file.name) 