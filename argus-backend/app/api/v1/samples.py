import hashlib
import logging
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Query, Form
from pymongo import DESCENDING

from app.core.storage import storage, upload_sample, delete_sample
from app.models.user import User
from app.models.sample import Sample, SampleResponse, SampleStats
from app.api.v1.auth import get_current_user
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/list", response_model=dict)
async def list_samples(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """
    获取样本列表
    """
    # 构建查询条件
    query = {}
    if search:
        query["$or"] = [
            {"file_name": {"$regex": search, "$options": "i"}},
            {"sha256_digest": {"$regex": search, "$options": "i"}},
            {"tags": {"$regex": search, "$options": "i"}}
        ]
    
    # 获取总数
    total = await Sample.find(query).count()
    
    # 获取分页数据
    samples = await Sample.find(query).skip(skip).limit(limit).to_list()
    
    # 转换为响应格式
    sample_list = []
    for sample in samples:
        # 获取上传者信息
        uploader = await sample.uploader.fetch()
        sample_list.append(
            SampleResponse(
                id=str(sample.id),
                file_name=sample.file_name,
                description=sample.description,
                file_path=sample.file_path,
                file_size=sample.file_size,
                file_type=sample.file_type,
                sha256_digest=sample.sha256_digest,
                upload_time=sample.upload_time,
                uploader=uploader.username,
                analysis_status=sample.analysis_status,
                analysis_results=sample.analysis_results,
                tags=sample.tags
            )
        )
    
    return {
        "data": sample_list,
        "total": total
    }

@router.post("/upload")
async def upload_sample_file(
    file: UploadFile = File(...),
    tags: List[str] = Form([]),
    description: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user)
):
    """
    上传样本文件
    """
    try:
        logger.info(f"开始上传文件: {file.filename}")
        
        # 检查文件大小
        file_content = await file.read()
        file_size = len(file_content)
        
        if file_size == 0:
            logger.error(f"文件内容为空: {file.filename}")
            raise HTTPException(
                status_code=400,
                detail="File is empty"
            )
        
        if file_size > settings.MAX_UPLOAD_SIZE:
            logger.error(f"文件大小超过限制: {file.filename} ({file_size} bytes)")
            raise HTTPException(
                status_code=400,
                detail=f"File size exceeds limit ({settings.MAX_UPLOAD_SIZE} bytes)"
            )
        
        # 计算SHA256
        sha256_digest = hashlib.sha256(file_content).hexdigest()
        logger.info(f"计算得到SHA256: {sha256_digest}")
        
        # 检查文件是否已存在
        existing_sample = await Sample.find_one({"sha256_digest": sha256_digest})
        if existing_sample:
            logger.info(f"样本已存在: {sha256_digest}")
            # 如果样本已存在，更新标签和描述（如果提供）
            if tags:
                existing_sample.tags = list(set(existing_sample.tags + tags))  # 合并标签并去重
            if description:
                existing_sample.description = description
            await existing_sample.save()
            
            return {
                "message": "Sample already exists, tags and description updated",
                "sha256_digest": sha256_digest,
                "file_path": existing_sample.file_path
            }
        
        # 生成文件路径
        file_path = f"{sha256_digest}"
        logger.info(f"生成文件路径: {file_path}")
        
        # 保存文件到存储
        try:
            if not await storage.save_file(file_path, file_content):
                logger.error(f"保存文件失败: {file_path}")
                raise HTTPException(
                    status_code=500,
                    detail="Failed to save file"
                )
            logger.info(f"文件保存成功: {file_path}")
        except Exception as e:
            logger.error(f"保存文件时发生错误: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to save file: {str(e)}"
            )
        
        # 创建样本记录
        try:
            sample = Sample(
                sha256_digest=sha256_digest,
                file_name=file.filename,
                file_size=file_size,
                file_type=file.content_type,
                file_path=file_path,
                tags=tags,
                description=description,
                uploader=current_user.id
            )
            
            await sample.save()
            logger.info(f"创建样本记录成功: {sha256_digest}")
            
            return {
                "message": "Sample uploaded successfully",
                "sha256_digest": sha256_digest,
                "file_path": file_path
            }
            
        except Exception as e:
            logger.error(f"创建样本记录时发生错误: {str(e)}")
            # 如果创建记录失败，删除已保存的文件
            await storage.delete_file(file_path)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create sample record: {str(e)}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"上传样本时发生错误: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to upload sample: {str(e)}"
        )

@router.get("/{sha256_digest}", response_model=SampleResponse)
async def get_sample(
    sha256_digest: str,
    current_user: User = Depends(get_current_user)
):
    """
    获取样本详情
    """
    sample = await Sample.find_one({"sha256_digest": sha256_digest})
    if not sample:
        raise HTTPException(
            status_code=404,
            detail="Sample not found"
        )
    
    # 获取上传者信息
    uploader = await sample.uploader.fetch()
    return SampleResponse(
        sha256_digest=sample.sha256_digest,
        file_name=sample.file_name,
        file_size=sample.file_size,
        file_type=sample.file_type,
        upload_time=sample.upload_time,
        tags=sample.tags,
        description=sample.description,
        uploader=uploader.username,
        analysis_status=sample.analysis_status,
        analysis_results=sample.analysis_results
    )

@router.delete("/{sha256_digest}")
async def delete_sample(
    sha256_digest: str,
    current_user: User = Depends(get_current_user)
):
    """
    删除样本
    """
    sample = await Sample.find_one({"sha256_digest": sha256_digest})
    if not sample:
        raise HTTPException(
            status_code=404,
            detail="Sample not found"
        )
    
    # 删除存储中的文件
    await storage.delete_file(sample.file_path)
    
    # 删除数据库记录
    await sample.delete()
    return {"message": "Sample deleted successfully"}

@router.get("/recent", response_model=List[SampleResponse])
async def get_recent_samples(
    limit: int = Query(5, ge=1, le=20),
    current_user: User = Depends(get_current_user)
):
    """获取最近添加的样本"""
    # 按上传时间倒序排序，限制返回数量
    samples = await Sample.find().sort("upload_time", DESCENDING).limit(limit).to_list()
    
    # 转换为响应格式
    sample_list = []
    for sample in samples:
        # 获取上传者信息
        uploader = await sample.uploader.fetch()
        sample_list.append(
            SampleResponse(
                sha256_digest=sample.sha256_digest,
                file_name=sample.file_name,
                file_size=sample.file_size,
                file_type=sample.file_type,
                upload_time=sample.upload_time,
                tags=sample.tags,
                description=sample.description,
                uploader=uploader.username,
                analysis_status=sample.analysis_status,
                analysis_results=sample.analysis_results
            )
        )
    
    return sample_list

@router.get("/stats", response_model=SampleStats)
async def get_sample_stats(current_user: User = Depends(get_current_user)):
    # 获取总样本数
    total_samples = await Sample.count()
    
    # 获取各状态的样本数量
    pipeline = [
        {"$group": {"_id": "$analysis_status", "count": {"$sum": 1}}}
    ]
    status_stats = await Sample.aggregate(pipeline).to_list()
    samples_by_status = {stat["_id"]: stat["count"] for stat in status_stats}
    
    # 获取各类型的样本数量
    pipeline = [
        {"$group": {"_id": "$file_type", "count": {"$sum": 1}}}
    ]
    type_stats = await Sample.aggregate(pipeline).to_list()
    samples_by_type = {stat["_id"]: stat["count"] for stat in type_stats}
    
    # 计算总存储量
    pipeline = [
        {"$group": {"_id": None, "total_size": {"$sum": "$file_size"}}}
    ]
    size_stats = await Sample.aggregate(pipeline).to_list()
    total_storage = size_stats[0]["total_size"] if size_stats else 0
    
    # 获取最近上传的样本
    recent_samples = await Sample.find().sort("upload_time", DESCENDING).limit(5).to_list()
    recent_uploads = [
        SampleResponse(
            sha256_digest=sample.sha256_digest,
            file_name=sample.file_name,
            file_size=sample.file_size,
            file_type=sample.file_type,
            upload_time=sample.upload_time,
            tags=sample.tags,
            description=sample.description,
            uploader=sample.uploader.username,
            analysis_status=sample.analysis_status,
            analysis_results=sample.analysis_results
        )
        for sample in recent_samples
    ]
    
    return SampleStats(
        total_samples=total_samples,
        total_storage=total_storage,
        samples_by_status=samples_by_status,
        samples_by_type=samples_by_type,
        recent_uploads=recent_uploads
    )

@router.get("/{sha256_digest}/download")
async def download_sample(
    sha256_digest: str,
    password: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """下载样本文件"""
    try:
        # 获取样本信息
        sample = await Sample.find_one({"sha256_digest": sha256_digest})
        if not sample:
            raise HTTPException(status_code=404, detail="Sample not found")
        
        if not sample.file_path:
            raise HTTPException(status_code=404, detail="File path not found")

        # 检查用户权限
        uploader = await sample.uploader.fetch()
        if not sample.is_public and uploader.id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to download this sample")

        # 如果提供了密码，创建加密的ZIP文件
        if password:
            logger.info(f"Creating encrypted ZIP file for sample: {sha256_digest}")
            zip_file_path = await storage.create_encrypted_zip(sample.file_path, password)
            if not zip_file_path:
                raise HTTPException(status_code=500, detail="Failed to create encrypted ZIP file")
            file_path = zip_file_path
        else:
            file_path = sample.file_path

        # 获取下载URL
        download_url = await storage.get_presigned_url(file_path)
        if not download_url:
            raise HTTPException(status_code=500, detail="Failed to generate download URL")

        return {
            "download_url": download_url,
            "file_name": sample.file_name,
            "file_type": "application/zip" if password else sample.file_type,
            "is_encrypted": password is not None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading sample: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error") 