import hashlib
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Query, Form
from pymongo import DESCENDING

from app.core.storage import storage, upload_sample, delete_sample
from app.models.user import User
from app.models.sample import Sample, SampleResponse, SampleStats, SampleBaseInfo
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
        
        if file_size > settings.MAX_FILE_SIZE:
            logger.error(f"文件大小超过限制: {file.filename} ({file_size} bytes)")
            raise HTTPException(
                status_code=400,
                detail=f"File size exceeds limit ({settings.MAX_FILE_SIZE} bytes)"
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
        file_path = await storage.generate_file_path(sha256_digest)
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
                file_name=file.filename,
                file_path=file_path,
                file_size=file_size,
                sha256_digest=sha256_digest,
                uploader=current_user.id,
                description=description,
                tags=tags
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

# 获取文件基本信息，用于详情页展示
@router.get("/{sha256_digest}/baseinfo", response_model=Dict[str, Any])
async def get_sample_baseinfo(
    sha256_digest: str,
    current_user: User = Depends(get_current_user)
):
    """获取样本的基本信息"""
    sample:Optional[Sample] = await Sample.find_one({"sha256_digest": sha256_digest})
    if not sample:
        raise HTTPException(
            status_code=404,
            detail="Sample not found"
        )
    try:
        if sample:
            base_info = SampleBaseInfo(
                fileName=sample.file_name,
                firstSubmit=sample.upload_time.isoformat() if sample.upload_time else '',
                lastSubmit=sample.upload_time.isoformat() if sample.upload_time else '',
                lastAnalysis=sample.upload_time.isoformat() if sample.upload_time else '',
                fileSize=sample.file_size,
                fileType=sample.magic_info.get('file_type', '') if sample.magic_info else '',
                detectionCount=5,
                engineCount=10,
                threatType='N/A',
                threatLevel='N/A',
                malwareFamily='N/A',
                malware_type_severity='low',
                threatTypeDesc='N/A',
                sha256=sample.sha256_digest,
                md5=sample.hash_info.get('md5', '') if sample.hash_info else '',
                sha1=sample.hash_info.get('sha1', '') if sample.hash_info else '',
            )
        return {
            'data': 
                base_info
        }
    except Exception as e:
        logger.error(f"获取{sha256_digest}文件基础信息失败{e}")
        raise HTTPException(
            status_code=500,
            detail="Sample not found"
        )


# 获取样本的行为检测
@router.get("/{sha256_digest}/behavior", response_model=Dict[str, Any])
async def get_sample_behavior(
    sha256_digest: str,
    current_user: User = Depends(get_current_user)
):
    """获取样本的行为检测"""
    # 暂时跳过返回固定的信息
    return {
        "data": [
          {
              "attck_id": "",
              "attck_info": {},
              "description": "{\"en\": \"Invoke COM-related apis\", \"cn\": \"调用COM相关API\"}",
              "families": [],
              "markcount": 2,
              "marks": [
                  {
                      "type": "generic",
                      "generic": {
                          "clasid": "{00000339-0000-0000-c000-000000000046}",
                          "api": "CoCreateInstance",
                          "iid": "{00000003-0000-0000-c000-000000000046}"
                      }
                  },
                  {
                      "type": "generic",
                      "generic": {
                          "clasid": "{c2f03a33-21f5-47fa-b4bb-156362a2f239}",
                          "api": "CoCreateInstance",
                          "iid": "{6d5140c1-7436-11ce-8034-00aa006009fa}"
                      }
                  }
              ],
              "name": "com_relation_api_call",
              "references": [],
              "severity": 1,
              "sig_class": "System Sensitive operation",
              "level": 1,
              "sandboxType": "Win10(1903 64bit,Office2016)",
              "severityStr": "general",
              "sigClassStr": "系统敏感操作"
          },
          {
              "attck_id": "",
              "attck_info": {},
              "description": "{\"en\": \"Creates a writable file in a temporary directory\", \"cn\": \"在临时目录中创建文件\"}",
              "families": [],
              "markcount": 6,
              "marks": [
                  {
                      "call": {
                          "tid": 6920,
                          "time": 1.744088843075871E12,
                          "api": "NtCreateFile",
                          "category": "file",
                          "status": 1,
                          "return_value": 0,
                          "arguments": {
                              "file_handle": "0x000002a4",
                              "desired_access": "0x40100080",
                              "file_attributes": 128,
                              "create_disposition": 5,
                              "create_options": 96,
                              "share_access": 3,
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM51D4.exe",
                              "filepath_r": "\\??\\C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\DEM51D4.exe",
                              "status_info": 2
                          },
                          "flags": {
                              "create_disposition": "FILE_OVERWRITE_IF",
                              "status_info": "FILE_CREATED",
                              "desired_access": "FILE_READ_ATTRIBUTES|SYNCHRONIZE|GENERIC_WRITE",
                              "file_attributes": "FILE_ATTRIBUTE_NORMAL",
                              "share_access": "FILE_SHARE_READ|FILE_SHARE_WRITE",
                              "create_options": "FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT"
                          },
                          "stacktrace": []
                      },
                      "pid": 6916,
                      "type": "call",
                      "cid": 21
                  },
                  {
                      "call": {
                          "tid": 6296,
                          "time": 1.7440888505460703E12,
                          "api": "NtCreateFile",
                          "category": "file",
                          "status": 1,
                          "return_value": 0,
                          "arguments": {
                              "file_handle": "0x000002a8",
                              "desired_access": "0x40100080",
                              "file_attributes": 128,
                              "create_disposition": 5,
                              "create_options": 96,
                              "share_access": 3,
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMAD71.exe",
                              "filepath_r": "\\??\\C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\DEMAD71.exe",
                              "status_info": 2
                          },
                          "flags": {
                              "create_disposition": "FILE_OVERWRITE_IF",
                              "status_info": "FILE_CREATED",
                              "desired_access": "FILE_READ_ATTRIBUTES|SYNCHRONIZE|GENERIC_WRITE",
                              "file_attributes": "FILE_ATTRIBUTE_NORMAL",
                              "share_access": "FILE_SHARE_READ|FILE_SHARE_WRITE",
                              "create_options": "FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT"
                          },
                          "stacktrace": []
                      },
                      "pid": 6300,
                      "type": "call",
                      "cid": 20
                  },
                  {
                      "call": {
                          "tid": 4828,
                          "time": 1.7440888422022695E12,
                          "api": "NtCreateFile",
                          "category": "file",
                          "status": 1,
                          "return_value": 0,
                          "arguments": {
                              "file_handle": "0x0000028c",
                              "desired_access": "0x40100080",
                              "file_attributes": 128,
                              "create_disposition": 5,
                              "create_options": 96,
                              "share_access": 3,
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5D2.exe",
                              "filepath_r": "\\??\\C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\DEM5D2.exe",
                              "status_info": 2
                          },
                          "flags": {
                              "create_disposition": "FILE_OVERWRITE_IF",
                              "status_info": "FILE_CREATED",
                              "desired_access": "FILE_READ_ATTRIBUTES|SYNCHRONIZE|GENERIC_WRITE",
                              "file_attributes": "FILE_ATTRIBUTE_NORMAL",
                              "share_access": "FILE_SHARE_READ|FILE_SHARE_WRITE",
                              "create_options": "FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT"
                          },
                          "stacktrace": []
                      },
                      "pid": 4840,
                      "type": "call",
                      "cid": 21
                  },
                  {
                      "call": {
                          "tid": 6948,
                          "time": 1.7440889430626914E12,
                          "api": "NtCreateFile",
                          "category": "file",
                          "status": 1,
                          "return_value": 0,
                          "arguments": {
                              "file_handle": "0x00000264",
                              "desired_access": "0x40100080",
                              "file_attributes": 128,
                              "create_disposition": 5,
                              "create_options": 96,
                              "share_access": 3,
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5F5C.exe",
                              "filepath_r": "\\??\\C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\DEM5F5C.exe",
                              "status_info": 2
                          },
                          "flags": {
                              "create_disposition": "FILE_OVERWRITE_IF",
                              "status_info": "FILE_CREATED",
                              "desired_access": "FILE_READ_ATTRIBUTES|SYNCHRONIZE|GENERIC_WRITE",
                              "file_attributes": "FILE_ATTRIBUTE_NORMAL",
                              "share_access": "FILE_SHARE_READ|FILE_SHARE_WRITE",
                              "create_options": "FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT"
                          },
                          "stacktrace": []
                      },
                      "pid": 6956,
                      "type": "call",
                      "cid": 20
                  },
                  {
                      "call": {
                          "tid": 3104,
                          "time": 1.74408890395242E12,
                          "api": "NtCreateFile",
                          "category": "file",
                          "status": 1,
                          "return_value": 0,
                          "arguments": {
                              "file_handle": "0x00000294",
                              "desired_access": "0x40100080",
                              "file_attributes": 128,
                              "create_disposition": 5,
                              "create_options": 96,
                              "share_access": 3,
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMB888.exe",
                              "filepath_r": "\\??\\C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\DEMB888.exe",
                              "status_info": 2
                          },
                          "flags": {
                              "create_disposition": "FILE_OVERWRITE_IF",
                              "status_info": "FILE_CREATED",
                              "desired_access": "FILE_READ_ATTRIBUTES|SYNCHRONIZE|GENERIC_WRITE",
                              "file_attributes": "FILE_ATTRIBUTE_NORMAL",
                              "share_access": "FILE_SHARE_READ|FILE_SHARE_WRITE",
                              "create_options": "FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT"
                          },
                          "stacktrace": []
                      },
                      "pid": 672,
                      "type": "call",
                      "cid": 22
                  },
                  {
                      "call": {
                          "tid": 3172,
                          "time": 1.7440889103272754E12,
                          "api": "NtCreateFile",
                          "category": "file",
                          "status": 1,
                          "return_value": 0,
                          "arguments": {
                              "file_handle": "0x000002a8",
                              "desired_access": "0x40100080",
                              "file_attributes": 128,
                              "create_disposition": 5,
                              "create_options": 96,
                              "share_access": 3,
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMFEF.exe",
                              "filepath_r": "\\??\\C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\DEMFEF.exe",
                              "status_info": 2
                          },
                          "flags": {
                              "create_disposition": "FILE_OVERWRITE_IF",
                              "status_info": "FILE_CREATED",
                              "desired_access": "FILE_READ_ATTRIBUTES|SYNCHRONIZE|GENERIC_WRITE",
                              "file_attributes": "FILE_ATTRIBUTE_NORMAL",
                              "share_access": "FILE_SHARE_READ|FILE_SHARE_WRITE",
                              "create_options": "FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT"
                          },
                          "stacktrace": []
                      },
                      "pid": 3160,
                      "type": "call",
                      "cid": 22
                  }
              ],
              "name": "create_file_intemp",
              "references": [],
              "severity": 1,
              "sig_class": "General",
              "level": 3,
              "sandboxType": "Win10(1903 64bit,Office2016)",
              "severityStr": "general",
              "sigClassStr": "一般行为"
          },
          {
              "attck_id": "",
              "attck_info": {},
              "description": "{\"en\": \"Creates executable files on the filesystem\", \"cn\": \"在文件系统上创建可执行文件\"}",
              "families": [],
              "markcount": 6,
              "marks": [
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              6300,
                              4840
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMAD71.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              6916,
                              6300
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM51D4.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              6956,
                              672
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5F5C.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              4840,
                              6956
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5D2.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              672,
                              3160
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMB888.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              3160
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMFEF.exe"
                      }
                  }
              ],
              "name": "creates_exe",
              "references": [],
              "severity": 1,
              "sig_class": "System Sensitive operation",
              "level": 1,
              "sandboxType": "Win10(1903 64bit,Office2016)",
              "severityStr": "general",
              "sigClassStr": "系统敏感操作"
          },
          {
              "attck_id": "T1082",
              "attck_info": {
                  "title": "System Information Discovery",
                  "Permissions Required": "User",
                  "Platform": "Linux, macOS, Windows",
                  "Data Sources": "Process command-line parameters, Process monitoring",
                  "Tactic": "Discovery",
                  "CAPEC ID": "CAPEC-311",
                  "ID": "T1082"
              },
              "description": "{\"en\": \"Contains functionality to query system information\", \"cn\": \"获取系统信息\"}",
              "families": [],
              "markcount": 5,
              "marks": [
                  {
                      "call": {
                          "tid": 6192,
                          "time": 1.744110624075871E12,
                          "api": "GetSystemInfo",
                          "category": "system",
                          "status": 1,
                          "return_value": 0,
                          "arguments": {
                              "processor_count": 4
                          },
                          "flags": {},
                          "stacktrace": []
                      },
                      "pid": 6916,
                      "type": "call",
                      "cid": 340
                  },
                  {
                      "call": {
                          "tid": 4832,
                          "time": 1.7441104755460703E12,
                          "api": "GetSystemInfo",
                          "category": "system",
                          "status": 1,
                          "return_value": 0,
                          "arguments": {
                              "processor_count": 4
                          },
                          "flags": {},
                          "stacktrace": []
                      },
                      "pid": 6300,
                      "type": "call",
                      "cid": 339
                  },
                  {
                      "call": {
                          "tid": 6884,
                          "time": 1.7441106552022695E12,
                          "api": "GetSystemInfo",
                          "category": "system",
                          "status": 1,
                          "return_value": 0,
                          "arguments": {
                              "processor_count": 4
                          },
                          "flags": {},
                          "stacktrace": []
                      },
                      "pid": 4840,
                      "type": "call",
                      "cid": 340
                  },
                  {
                      "call": {
                          "tid": 1928,
                          "time": 1.7441106300626914E12,
                          "api": "GetSystemInfo",
                          "category": "system",
                          "status": 1,
                          "return_value": 0,
                          "arguments": {
                              "processor_count": 4
                          },
                          "flags": {},
                          "stacktrace": []
                      },
                      "pid": 6956,
                      "type": "call",
                      "cid": 340
                  },
                  {
                      "call": {
                          "tid": 7032,
                          "time": 1.74411040395242E12,
                          "api": "GetSystemInfo",
                          "category": "system",
                          "status": 1,
                          "return_value": 0,
                          "arguments": {
                              "processor_count": 4
                          },
                          "flags": {},
                          "stacktrace": []
                      },
                      "pid": 672,
                      "type": "call",
                      "cid": 342
                  }
              ],
              "name": "getsysteminfo",
              "references": [],
              "severity": 1,
              "sig_class": "Environment Awareness",
              "level": 8,
              "sandboxType": "Win10(1903 64bit,Office2016)",
              "severityStr": "general",
              "sigClassStr": "系统环境探测"
          },
          {
              "attck_id": "",
              "attck_info": {},
              "description": "{\"en\": \"This executable has a PDB path\", \"cn\": \"这个可执行文件存在调试数据库文件（PDB）路径\"}",
              "families": [],
              "markcount": 1,
              "marks": [
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [],
                          "category": "pdb_path",
                          "ioc": "C:\\ping_pong\\win_client\\Release\\win_client.pdb"
                      }
                  }
              ],
              "name": "has_pdb",
              "references": [],
              "severity": 1,
              "sig_class": "General",
              "level": 3,
              "sandboxType": "Win10(1903 64bit,Office2016)",
              "severityStr": "general",
              "sigClassStr": "一般行为"
          },
          {
              "attck_id": "",
              "attck_info": {},
              "description": "{\"en\": \"Drops a binary and executes it\", \"cn\": \"释放了一个二进制文件并执行\"}",
              "families": [],
              "markcount": 5,
              "marks": [
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              6916,
                              6300
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM51D4.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              6300,
                              4840
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMAD71.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              4840,
                              6956
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5D2.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              6956,
                              672
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5F5C.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              672,
                              3160
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMB888.exe"
                      }
                  }
              ],
              "name": "dropper",
              "references": [],
              "severity": 2,
              "sig_class": "General",
              "level": 3,
              "sandboxType": "Win10(1903 64bit,Office2016)",
              "severityStr": "suspicious",
              "sigClassStr": "一般行为"
          },
          {
              "attck_id": "",
              "attck_info": {},
              "description": "{\"en\": \"One or more martian processes was created\", \"cn\": \"创建一个或多个可疑进程\"}",
              "families": [],
              "markcount": 5,
              "marks": [
                  {
                      "type": "generic",
                      "generic": {
                          "parent_process": "8038e5.exe",
                          "martian_process": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM51D4.exe"
                      }
                  },
                  {
                      "type": "generic",
                      "generic": {
                          "parent_process": "dem51d4.exe",
                          "martian_process": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMAD71.exe"
                      }
                  },
                  {
                      "type": "generic",
                      "generic": {
                          "parent_process": "demad71.exe",
                          "martian_process": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5D2.exe"
                      }
                  },
                  {
                      "type": "generic",
                      "generic": {
                          "parent_process": "dem5d2.exe",
                          "martian_process": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5F5C.exe"
                      }
                  },
                  {
                      "type": "generic",
                      "generic": {
                          "parent_process": "dem5f5c.exe",
                          "martian_process": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMB888.exe"
                      }
                  }
              ],
              "name": "process_martian",
              "references": [],
              "severity": 2,
              "sig_class": "System Sensitive operation",
              "level": 1,
              "sandboxType": "Win10(1903 64bit,Office2016)",
              "severityStr": "suspicious",
              "sigClassStr": "系统敏感操作"
          },
          {
              "attck_id": "",
              "attck_info": {},
              "description": "{\"en\": \"Creates an executable file in a user folder\", \"cn\": \"在用户目录下创建可执行文件\"}",
              "families": [
                  "persistance"
              ],
              "markcount": 6,
              "marks": [
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              6916,
                              6300
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM51D4.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              6300,
                              4840
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMAD71.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              4840,
                              6956
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5D2.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              6956,
                              672
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5F5C.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              672,
                              3160
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMB888.exe"
                      }
                  },
                  {
                      "type": "ioc",
                      "ioc": {
                          "pid": [
                              3160
                          ],
                          "category": "file",
                          "ioc": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMFEF.exe"
                      }
                  }
              ],
              "name": "creates_user_folder_exe",
              "references": [],
              "severity": 3,
              "sig_class": "System Sensitive operation",
              "level": 1,
              "sandboxType": "Win10(1903 64bit,Office2016)",
              "severityStr": "malicious",
              "sigClassStr": "系统敏感操作"
          },
          {
              "attck_id": "",
              "attck_info": {},
              "description": "{\"en\": \"Creates a slightly modified copy of itself\", \"cn\": \"创建一个微改过的拷贝\"}",
              "families": [],
              "markcount": 6,
              "marks": [
                  {
                      "type": "generic",
                      "generic": {
                          "file": {
                              "name": "DEM51D4.exe",
                              "path": "files/551ba0f0ef687b10afb7976341d908789486f01b472d509011bb59739d350cb8/DEM51D4.exe",
                              "size": 14912,
                              "crc32": "8656F7DD",
                              "md5": "31981faea6e052969540e172057f1e28",
                              "sha1": "ca9279b53e2e4ed908e6888ae63b5de179479705",
                              "sha256": "551ba0f0ef687b10afb7976341d908789486f01b472d509011bb59739d350cb8",
                              "sha512": "44468f7f7141bb3c20be4dd57bb7064879d995dcdd1cbc4c688adb96d5c51d048292475b6e747d0381a5a3b2df0f9153d6d386afc9db0fb42a00ce1ed3a9daa5",
                              "ssdeep": "384:hdtXWiJCQxsEwvK3RpSSHuGQG2Rqm4YhYEM:hDXWipuE+K3/SSHgxmX",
                              "type": "PE32 executable (console) Intel 80386, for MS Windows",
                              "yara": [],
                              "domains": [],
                              "ips": [],
                              "urls": [],
                              "mails": [],
                              "pids": [
                                  6916
                              ],
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM51D4.exe",
                              "create_type": "CLOSE",
                              "paths": [
                                  "c:\\users\\administrator\\appdata\\local\\temp\\dem51d4.exe"
                              ],
                              "download": []
                          }
                      }
                  },
                  {
                      "type": "generic",
                      "generic": {
                          "file": {
                              "name": "DEMAD71.exe",
                              "path": "files/abb3f5a65efa08126c98abcd7ad85c42c8cb75a87c534f4bbcb808c90acd35e5/DEMAD71.exe",
                              "size": 14928,
                              "crc32": "8E80FD6A",
                              "md5": "0ebee36a8ceda3e9115b519d96a407a1",
                              "sha1": "f23ccf6990f109b836b5bea791c4ba8f90fd0184",
                              "sha256": "abb3f5a65efa08126c98abcd7ad85c42c8cb75a87c534f4bbcb808c90acd35e5",
                              "sha512": "c33dd6910bd85347e6b8e6b430a2fed20b0a75b624f0f0ec9c3ed50047b0eed143fc7b6c2f6b2aa8eaeb55a55830f2201b4c2110b4632dd5cf5ef860930e875c",
                              "ssdeep": "384:hdtXWiJCQxsEwvK3RpSSHuGQG2Rqm4YhYEY:hDXWipuE+K3/SSHgxm3",
                              "type": "PE32 executable (console) Intel 80386, for MS Windows",
                              "yara": [],
                              "domains": [],
                              "ips": [],
                              "urls": [],
                              "mails": [],
                              "pids": [
                                  6300
                              ],
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMAD71.exe",
                              "create_type": "CLOSE",
                              "paths": [
                                  "c:\\users\\administrator\\appdata\\local\\temp\\demad71.exe"
                              ],
                              "download": []
                          }
                      }
                  },
                  {
                      "type": "generic",
                      "generic": {
                          "file": {
                              "name": "DEM5D2.exe",
                              "path": "files/bb25ae27043c87f776464f0be6a6a16a70492b0387a2a826e5e6ec135440c9d6/DEM5D2.exe",
                              "size": 14944,
                              "crc32": "F3B65C62",
                              "md5": "b451e69aba2b4663d2e2532f82fe2556",
                              "sha1": "4efb8c72472a9b37d29e7424f9a2b13f8710101c",
                              "sha256": "bb25ae27043c87f776464f0be6a6a16a70492b0387a2a826e5e6ec135440c9d6",
                              "sha512": "def321a89a5f5d9273c1cf240d03c30250ac1ab0c9b8a61b80798adf4c4169f545563b718d00373166a31f9f36c745f33848633f9ae84bbb7012514815899f7f",
                              "ssdeep": "384:hdtXWiJCQxsEwvK3RpSSHuGQG2Rqm4YhYEm:hDXWipuE+K3/SSHgxmp",
                              "type": "PE32 executable (console) Intel 80386, for MS Windows",
                              "yara": [],
                              "domains": [],
                              "ips": [],
                              "urls": [],
                              "mails": [],
                              "pids": [
                                  4840
                              ],
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5D2.exe",
                              "create_type": "CLOSE",
                              "paths": [
                                  "c:\\users\\administrator\\appdata\\local\\temp\\dem5d2.exe"
                              ],
                              "download": []
                          }
                      }
                  },
                  {
                      "type": "generic",
                      "generic": {
                          "file": {
                              "name": "DEM5F5C.exe",
                              "path": "files/56995ea483efed80ce3ebfa5f614b35125ef05579e9521dd73231c9882f10a84/DEM5F5C.exe",
                              "size": 14960,
                              "crc32": "B8485951",
                              "md5": "d3028702a28ccc7306c643bbeaeeac70",
                              "sha1": "7538fbbe0afdde8880ebf9131ddc603e35a021c2",
                              "sha256": "56995ea483efed80ce3ebfa5f614b35125ef05579e9521dd73231c9882f10a84",
                              "sha512": "dee563c75427a5151095a081bbd3df03f3afea3b9195b7ad3fbbc23e0f5a8ac8a8778f438100b0b2c03f0a2bbdc661c99ad9fb0bdfcf929fe798bacb8c7a79c5",
                              "ssdeep": "384:hdtXWiJCQxsEwvK3RpSSHuGQG2Rqm4YhYE1:hDXWipuE+K3/SSHgxm2",
                              "type": "PE32 executable (console) Intel 80386, for MS Windows",
                              "yara": [],
                              "domains": [],
                              "ips": [],
                              "urls": [],
                              "mails": [],
                              "pids": [
                                  6956
                              ],
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEM5F5C.exe",
                              "create_type": "CLOSE",
                              "paths": [
                                  "c:\\users\\administrator\\appdata\\local\\temp\\dem5f5c.exe"
                              ],
                              "download": []
                          }
                      }
                  },
                  {
                      "type": "generic",
                      "generic": {
                          "file": {
                              "name": "DEMB888.exe",
                              "path": "files/8cc354b4cb649e7380b142dc99bddbfb1c60fedc04b8d8a8ecfc800e4987b58f/DEMB888.exe",
                              "size": 14976,
                              "crc32": "2FD8F122",
                              "md5": "c59b2ca064d697151bddd808796bd60a",
                              "sha1": "f290b507a00d20ba53014376cdb7a7782b8f5526",
                              "sha256": "8cc354b4cb649e7380b142dc99bddbfb1c60fedc04b8d8a8ecfc800e4987b58f",
                              "sha512": "f59c38541a5132f2042d20f18e97ae001c02bcade51be1e0a98c6a3db738173bf8a5579b1d8074c491d828381aceea35a378fecce297fe54425330fb99d43048",
                              "ssdeep": "384:hdtXWiJCQxsEwvK3RpSSHuGQG2Rqm4YhYET:hDXWipuE+K3/SSHgxm8",
                              "type": "PE32 executable (console) Intel 80386, for MS Windows",
                              "yara": [],
                              "domains": [],
                              "ips": [],
                              "urls": [],
                              "mails": [],
                              "pids": [
                                  672
                              ],
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMB888.exe",
                              "create_type": "CLOSE",
                              "paths": [
                                  "c:\\users\\administrator\\appdata\\local\\temp\\demb888.exe"
                              ],
                              "download": []
                          }
                      }
                  },
                  {
                      "type": "generic",
                      "generic": {
                          "file": {
                              "name": "DEMFEF.exe",
                              "path": "files/35f18c3d0299bd98e3b3104a7ef274b15f825da20cc2a7160205a93c011adc52/DEMFEF.exe",
                              "size": 14992,
                              "crc32": "3E33CA7A",
                              "md5": "3290fbc1f2b9df79bc98a52017b3b576",
                              "sha1": "c8a639855fa9ff4d57f8f642c6347fa444be128c",
                              "sha256": "35f18c3d0299bd98e3b3104a7ef274b15f825da20cc2a7160205a93c011adc52",
                              "sha512": "28553b90bbbbb28f0f1aa4c63d143b5143eb2df0269d8c8c7cfb0bdf3f7d15c83ae82e9c004f57540bf362e3d0d1b0568494da2d48212025817a05db2de7468c",
                              "ssdeep": "384:hdtXWiJCQxsEwvK3RpSSHuGQG2Rqm4YhYEe:hDXWipuE+K3/SSHgxmh",
                              "type": "PE32 executable (console) Intel 80386, for MS Windows",
                              "yara": [],
                              "domains": [],
                              "ips": [],
                              "urls": [],
                              "mails": [],
                              "pids": [
                                  3160
                              ],
                              "filepath": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\DEMFEF.exe",
                              "create_type": "CLOSE",
                              "paths": [
                                  "c:\\users\\administrator\\appdata\\local\\temp\\demfef.exe"
                              ],
                              "download": []
                          }
                      }
                  }
              ],
              "name": "packer_polymorphic",
              "references": [],
              "severity": 3,
              "sig_class": "General",
              "level": 3,
              "sandboxType": "Win10(1903 64bit,Office2016)",
              "severityStr": "malicious",
              "sigClassStr": "一般行为"
          }
      ]
    }

# 获取样本命中的yara规则
@router.get("/{sha256_digest}/yara", response_model=Dict[str, Any])
async def get_sample_yara(
    sha256_digest: str,
    current_user: User = Depends(get_current_user)
):
    """获取样本命中的YARA规则"""
    # 暂时跳过返回固定的信息
    return {
        "data":{
          "grouped": {
              "tsmam": {
                  "Win10(1903 64bit,Office2016)": [
                      {
                          "name": "suspicious_packer_section",
                          "description": "The packer/protector section names/keywords",
                          "sha256": None,
                          "path": "b6455d6e9a931e2c_7504_5969047944310442025",
                          "matches": [
                              "UPX!",
                              "UPX0",
                              "UPX1"
                          ],
                          "source": "Github",
                          "sandboxType": [
                              "Win10(1903 64bit,Office2016)"
                          ],
                          "sbType": "Win10(1903 64bit,Office2016)"
                      },
                      {
                          "name": "UPX",
                          "description": "(no description)",
                          "sha256": None,
                          "path": "b6455d6e9a931e2c_7504_5969047944310442025",
                          "matches": [
                              "UPX!",
                              "UPX0",
                              "UPX1"
                          ],
                          "source": "Github",
                          "sandboxType": [
                              "Win10(1903 64bit,Office2016)"
                          ],
                          "sbType": "Win10(1903 64bit,Office2016)"
                      },
                      {
                          "name": "shellcode",
                          "description": "Matched shellcode byte patterns",
                          "sha256": None,
                          "path": "fd4909a0d0e51318_7504_939301044310442025",
                          "matches": [
                              "558bec81ec",
                              "648b3530"
                          ],
                          "source": "General",
                          "sandboxType": [
                              "Win10(1903 64bit,Office2016)"
                          ],
                          "sbType": "Win10(1903 64bit,Office2016)"
                      },
                      {
                          "name": "NanoCore",
                          "description": "(no description)",
                          "sha256": None,
                          "path": "878535c339d56481_7504_63265001044310442025",
                          "matches": [
                              "ClientPlugin",
                              "LogClientMessage",
                              "NanoCore",
                              "ProjectData"
                          ],
                          "source": "General",
                          "sandboxType": [
                              "Win10(1903 64bit,Office2016)"
                          ],
                          "sbType": "Win10(1903 64bit,Office2016)"
                      },
                      {
                          "name": "NanoCore_1",
                          "description": "(no description)",
                          "sha256": None,
                          "path": "878535c339d56481_7504_63265001044310442025",
                          "matches": [
                              "#=q",
                              "ClientPlugin",
                              "DESCrypto",
                              "KeepAlive",
                              "LogClientMessage",
                              "NanoCore",
                              "ProjectData",
                              "get_Connected"
                          ],
                          "source": "General",
                          "sandboxType": [
                              "Win10(1903 64bit,Office2016)"
                          ],
                          "sbType": "Win10(1903 64bit,Office2016)"
                      },
                      {
                          "name": "MALWARE_Win_NanoCore",
                          "description": "(no description)",
                          "sha256": None,
                          "path": "878535c339d56481_7504_63265001044310442025",
                          "matches": [
                              "ClientPlugin",
                              "EndPoint",
                              "IClientNameObjectCollection",
                              "IClientNetwork",
                              "IClientNetworkHost",
                              "IClientApp",
                              "IClientAppHost",
                              "IClientData",
                              "IClientDataHost",
                              "IClientLoggingHost",
                              "IClientReadOnlyNameObjectCollection",
                              "IClientUIHost",
                              "IPAddress",
                              "IPEndPoint",
                              "NanoCore Client",
                              "NanoCore.ClientPlugin",
                              "NanoCore.ClientPluginHost",
                              "get_ClientSettings",
                              "get_Connected"
                          ],
                          "source": "General",
                          "sandboxType": [
                              "Win10(1903 64bit,Office2016)"
                          ],
                          "sbType": "Win10(1903 64bit,Office2016)"
                      },
                      {
                          "name": "Windows_Trojan_Nanocore_d8c4e3c5",
                          "description": "(no description)",
                          "sha256": None,
                          "path": "878535c339d56481_7504_63265001044310442025",
                          "matches": [
                              "ClientLoaderForm.resources",
                              "AddHostEntry",
                              "GetBlockHash",
                              "IClientAppHost",
                              "IClientLoggingHost",
                              "LogClientException",
                              "NanoCore.ClientPlugin",
                              "NanoCore.ClientPluginHost",
                              "PipeExists",
                              "PluginCommand",
                              "get_BuilderSettings"
                          ],
                          "source": "General",
                          "sandboxType": [
                              "Win10(1903 64bit,Office2016)"
                          ],
                          "sbType": "Win10(1903 64bit,Office2016)"
                      },
                      {
                          "name": "Nanocore",
                          "description": "detect Nanocore in memory",
                          "sha256": None,
                          "path": "878535c339d56481_7504_63265001044310442025",
                          "matches": [
                              "CommandType",
                              "NanoCore Client",
                              "PluginCommand"
                          ],
                          "source": "Github",
                          "sandboxType": [
                              "Win10(1903 64bit,Office2016)"
                          ],
                          "sbType": "Win10(1903 64bit,Office2016)"
                      },
                      {
                          "name": "Nanocore_RAT_Gen_2",
                          "description": "Detetcs the Nanocore RAT",
                          "sha256": None,
                          "path": "878535c339d56481_7504_63265001044310442025",
                          "matches": [
                              "#=qjgz7ljmpp0J7FvL9dmi8ctJILdgtcbw8JYUc6GC8MeJ9B11Crfg2Djxcf0p8PZGe",
                              "IClientNetworkHost",
                              "NanoCore.ClientPluginHost"
                          ],
                          "source": "Github",
                          "sandboxType": [
                              "Win10(1903 64bit,Office2016)"
                          ],
                          "sbType": "Win10(1903 64bit,Office2016)"
                      },
                      {
                          "name": "NanoCore",
                          "description": "(no description)",
                          "sha256": None,
                          "path": "878535c339d56481_7504_63265001044310442025",
                          "matches": [
                              "#=q",
                              "ClientPlugin",
                              "DESCrypto",
                              "KeepAlive",
                              "LogClientMessage",
                              "NanoCore",
                              "ProjectData",
                              "get_Connected"
                          ],
                          "source": "Github",
                          "sandboxType": [
                              "Win10(1903 64bit,Office2016)"
                          ],
                          "sbType": "Win10(1903 64bit,Office2016)"
                      }
                  ]
              },
              "dropped": {},
              "target": {}
          },
          "sandboxtypes": [
              "Win10(1903 64bit,Office2016)"
          ],
          "merged": {
              "tsmam": [
                  {
                      "name": "MALWARE_Win_NanoCore",
                      "description": "(no description)",
                      "sha256": None,
                      "path": "878535c339d56481_7504_63265001044310442025",
                      "matches": [
                          "ClientPlugin",
                          "EndPoint",
                          "IClientNameObjectCollection",
                          "IClientNetwork",
                          "IClientNetworkHost",
                          "IClientApp",
                          "IClientAppHost",
                          "IClientData",
                          "IClientDataHost",
                          "IClientLoggingHost",
                          "IClientReadOnlyNameObjectCollection",
                          "IClientUIHost",
                          "IPAddress",
                          "IPEndPoint",
                          "NanoCore Client",
                          "NanoCore.ClientPlugin",
                          "NanoCore.ClientPluginHost",
                          "get_ClientSettings",
                          "get_Connected"
                      ],
                      "source": "General",
                      "sandboxType": [
                          "Win10(1903 64bit,Office2016)"
                      ],
                      "sbType": "Win10(1903 64bit,Office2016)"
                  },
                  {
                      "name": "shellcode",
                      "description": "Matched shellcode byte patterns",
                      "sha256": None,
                      "path": "fd4909a0d0e51318_7504_939301044310442025",
                      "matches": [
                          "558bec81ec",
                          "648b3530"
                      ],
                      "source": "General",
                      "sandboxType": [
                          "Win10(1903 64bit,Office2016)"
                      ],
                      "sbType": "Win10(1903 64bit,Office2016)"
                  },
                  {
                      "name": "suspicious_packer_section",
                      "description": "The packer/protector section names/keywords",
                      "sha256": None,
                      "path": "b6455d6e9a931e2c_7504_5969047944310442025",
                      "matches": [
                          "UPX!",
                          "UPX0",
                          "UPX1"
                      ],
                      "source": "Github",
                      "sandboxType": [
                          "Win10(1903 64bit,Office2016)"
                      ],
                      "sbType": "Win10(1903 64bit,Office2016)"
                  },
                  {
                      "name": "NanoCore_1",
                      "description": "(no description)",
                      "sha256": None,
                      "path": "878535c339d56481_7504_63265001044310442025",
                      "matches": [
                          "#=q",
                          "ClientPlugin",
                          "DESCrypto",
                          "KeepAlive",
                          "LogClientMessage",
                          "NanoCore",
                          "ProjectData",
                          "get_Connected"
                      ],
                      "source": "General",
                      "sandboxType": [
                          "Win10(1903 64bit,Office2016)"
                      ],
                      "sbType": "Win10(1903 64bit,Office2016)"
                  },
                  {
                      "name": "Windows_Trojan_Nanocore_d8c4e3c5",
                      "description": "(no description)",
                      "sha256": None,
                      "path": "878535c339d56481_7504_63265001044310442025",
                      "matches": [
                          "ClientLoaderForm.resources",
                          "AddHostEntry",
                          "GetBlockHash",
                          "IClientAppHost",
                          "IClientLoggingHost",
                          "LogClientException",
                          "NanoCore.ClientPlugin",
                          "NanoCore.ClientPluginHost",
                          "PipeExists",
                          "PluginCommand",
                          "get_BuilderSettings"
                      ],
                      "source": "General",
                      "sandboxType": [
                          "Win10(1903 64bit,Office2016)"
                      ],
                      "sbType": "Win10(1903 64bit,Office2016)"
                  },
                  {
                      "name": "UPX",
                      "description": "(no description)",
                      "sha256": None,
                      "path": "b6455d6e9a931e2c_7504_5969047944310442025",
                      "matches": [
                          "UPX!",
                          "UPX0",
                          "UPX1"
                      ],
                      "source": "Github",
                      "sandboxType": [
                          "Win10(1903 64bit,Office2016)"
                      ],
                      "sbType": "Win10(1903 64bit,Office2016)"
                  },
                  {
                      "name": "NanoCore",
                      "description": "(no description)",
                      "sha256": None,
                      "path": "878535c339d56481_7504_63265001044310442025",
                      "matches": [
                          "#=q",
                          "ClientPlugin",
                          "DESCrypto",
                          "KeepAlive",
                          "LogClientMessage",
                          "NanoCore",
                          "ProjectData",
                          "get_Connected"
                      ],
                      "source": "Github",
                      "sandboxType": [
                          "Win10(1903 64bit,Office2016)"
                      ],
                      "sbType": "Win10(1903 64bit,Office2016)"
                  },
                  {
                      "name": "Nanocore",
                      "description": "detect Nanocore in memory",
                      "sha256": None,
                      "path": "878535c339d56481_7504_63265001044310442025",
                      "matches": [
                          "CommandType",
                          "NanoCore Client",
                          "PluginCommand"
                      ],
                      "source": "Github",
                      "sandboxType": [
                          "Win10(1903 64bit,Office2016)"
                      ],
                      "sbType": "Win10(1903 64bit,Office2016)"
                  },
                  {
                      "name": "NanoCore",
                      "description": "(no description)",
                      "sha256": None,
                      "path": "878535c339d56481_7504_63265001044310442025",
                      "matches": [
                          "ClientPlugin",
                          "LogClientMessage",
                          "NanoCore",
                          "ProjectData"
                      ],
                      "source": "General",
                      "sandboxType": [
                          "Win10(1903 64bit,Office2016)"
                      ],
                      "sbType": "Win10(1903 64bit,Office2016)"
                  },
                  {
                      "name": "Nanocore_RAT_Gen_2",
                      "description": "Detetcs the Nanocore RAT",
                      "sha256": None,
                      "path": "878535c339d56481_7504_63265001044310442025",
                      "matches": [
                          "#=qjgz7ljmpp0J7FvL9dmi8ctJILdgtcbw8JYUc6GC8MeJ9B11Crfg2Djxcf0p8PZGe",
                          "IClientNetworkHost",
                          "NanoCore.ClientPluginHost"
                      ],
                      "source": "Github",
                      "sandboxType": [
                          "Win10(1903 64bit,Office2016)"
                      ],
                      "sbType": "Win10(1903 64bit,Office2016)"
                  }
              ],
              "dropped": [],
              "target": []
          }
      }
    }

# 获取样本命中的sigma规则
@router.get("/{sha256_digest}/sigma", response_model=Dict[str, Any])
async def get_sample_sigma(
    sha256_digest: str,
    current_user: User = Depends(get_current_user)
):
    """获取样本命中的sigma规则"""
    # 暂时跳过返回固定的信息
    return {
        "data": {
            "sigma_rules": []
        }
    }

# 获取样本的多引擎检测结果
@router.get("/{sha256_digest}/multi_engine_detection", response_model=Dict[str, Any])
async def get_sample_multi_engine_detection(
    sha256_digest: str,
    current_user: User = Depends(get_current_user)
):
    """获取样本的多引擎检测结果"""
    # 暂时跳过返回固定的信息
    return {
        "data": {
            "total": 28,
            "recent_scan": "2025-04-08 13:12:44",
            "report_num": 12,
            "engine_result": [
            {
                "result": "Trojan:Win32/Vindor!pz",
                "engine": "Microsoft",
                "engine_desc": "微软（MSE）"
            },
            {
                "result": "a variant of Win32/Agent.ADRA trojan",
                "engine": "ESET",
                "engine_desc": "ESET"
            },
            {
                "result": "Trojan.PiPong",
                "engine": "IKARUS",
                "engine_desc": "IKARUS"
            },
            {
                "result": "Trojan.Siggen15.32258",
                "engine": "Dr.Web",
                "engine_desc": "大蜘蛛（Dr.Web）"
            },
            {
                "result": "Win32:TrojanX-gen",
                "engine": "Avast",
                "engine_desc": "Avast"
            },
            {
                "result": "Win32:TrojanX-gen",
                "engine": "AVG",
                "engine_desc": "AVG"
            },
            {
                "result": "Generic.Dacic.310FD38C.A.1B9B4BCC",
                "engine": "GDATA",
                "engine_desc": "GDATA"
            },
            {
                "result": "Trojan ( 0058a19d1 )",
                "engine": "K7",
                "engine_desc": "K7"
            },
            {
                "result": "Trojan/Win32.Vindor",
                "engine": "Antiy",
                "engine_desc": "安天（Antiy）"
            },
            {
                "result": "Trojan.Agent.douz",
                "engine": "JiangMin",
                "engine_desc": "江民（JiangMin）"
            },
            {
                "result": "Trojan.Win32.TrjGen.jidpck",
                "engine": "NANO",
                "engine_desc": "NANO"
            },
            {
                "result": "Trj/Genetic.gen",
                "engine": "Panda",
                "engine_desc": "熊猫（Panda）"
            },
            {
                "result": "safe",
                "engine": "Kaspersky",
                "engine_desc": "卡巴斯基（Kaspersky）"
            },
            {
                "result": "safe",
                "engine": "Avira",
                "engine_desc": "小红伞（Avira）"
            },
            {
                "result": "safe",
                "engine": "Qihu360",
                "engine_desc": "360（Qihoo 360）"
            },
            {
                "result": "safe",
                "engine": "Baidu",
                "engine_desc": "Baidu"
            },
            {
                "result": "safe",
                "engine": "Trustlook",
                "engine_desc": "Trustlook"
            },
            {
                "result": "safe",
                "engine": "Rising",
                "engine_desc": "瑞星（Rising）"
            },
            {
                "result": "safe",
                "engine": "Sophos",
                "engine_desc": "Sophos"
            },
            {
                "result": "safe",
                "engine": "ClamAV",
                "engine_desc": "ClamAV"
            },
            {
                "result": "safe",
                "engine": "vbwebshell",
                "engine_desc": "WebShell专杀"
            },
            {
                "result": "safe",
                "engine": "Baidu-China",
                "engine_desc": "Baidu-China"
            },
            {
                "result": "safe",
                "engine": "MicroAPT",
                "engine_desc": "MicroAPT"
            },
            {
                "result": "safe",
                "engine": "OneAV",
                "engine_desc": "OneAV"
            },
            {
                "result": "safe",
                "engine": "OneStatic",
                "engine_desc": "OneStatic"
            },
            {
                "result": "safe",
                "engine": "NonePe",
                "engine_desc": "MicroNonPE"
            },
            {
                "result": "safe",
                "engine": "PwSH",
                "engine_desc": "OneAV-PWSH"
            },
            {
                "result": "safe",
                "engine": "ShellPub",
                "engine_desc": "ShellPub"
            }]
        }
    }