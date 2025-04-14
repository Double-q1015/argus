from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from typing import List
from app.core.security import get_current_user
from app.models.user import User
from app.schemas.sample import SampleCreate, SampleResponse
from app.services.sample_service import SampleService

router = APIRouter()

@router.post("/samples/", response_model=SampleResponse)
async def create_sample(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    sample_service: SampleService = Depends()
):
    """上传新的样本文件"""
    return await sample_service.create_sample(file, current_user.id)

@router.get("/samples/", response_model=List[SampleResponse])
async def get_samples(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    sample_service: SampleService = Depends()
):
    """获取样本列表"""
    return await sample_service.get_samples(current_user.id, skip, limit)

@router.get("/samples/{sample_id}", response_model=SampleResponse)
async def get_sample(
    sample_id: str,
    current_user: User = Depends(get_current_user),
    sample_service: SampleService = Depends()
):
    """获取单个样本详情"""
    sample = await sample_service.get_sample(sample_id, current_user.id)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    return sample

@router.delete("/samples/{sample_id}")
async def delete_sample(
    sample_id: str,
    current_user: User = Depends(get_current_user),
    sample_service: SampleService = Depends()
):
    """删除样本"""
    success = await sample_service.delete_sample(sample_id, current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="Sample not found")
    return {"message": "Sample deleted successfully"} 