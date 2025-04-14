from typing import List
from fastapi import APIRouter, HTTPException, Depends
from app.models.yara import YaraRule, YaraRuleCreate, YaraRuleUpdate, YaraRuleResponse
from app.core.yara_manager import YaraManager
from app.core.security import get_current_user
from app.models.user import User
from datetime import datetime
from bson import ObjectId
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/rules", response_model=YaraRuleResponse)
async def create_rule(
    rule: YaraRuleCreate,
    current_user: User = Depends(get_current_user)
):
    """创建新的Yara规则"""
    # 检查规则名称是否已存在
    existing_rule = await YaraRule.find_one({"name": rule.name})
    if existing_rule:
        raise HTTPException(status_code=400, detail="规则名称已存在")
    
    # 验证规则语法
    is_valid, error = await YaraManager.validate_rule(rule.content)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"规则语法错误: {error}")
    
    # 创建新规则
    new_rule = YaraRule(
        name=rule.name,
        description=rule.description,
        content=rule.content,
        creator=current_user,
        is_public=rule.is_public,
        tags=rule.tags,
        metadata=rule.metadata
    )
    await new_rule.insert()
    
    return YaraRuleResponse(
        id=str(new_rule.id),
        name=new_rule.name,
        description=new_rule.description,
        content=new_rule.content,
        creator=str(new_rule.creator.id),
        created_at=new_rule.created_at,
        updated_at=new_rule.updated_at,
        is_active=new_rule.is_active,
        is_public=new_rule.is_public,
        tags=new_rule.tags,
        metadata=new_rule.metadata
    )

@router.get("/rules", response_model=dict)
async def list_rules(
    skip: int = 0,
    limit: int = 10,
    current_user: User = Depends(get_current_user)
):
    """获取Yara规则列表，只返回当前用户创建的规则"""
    try:
        # 获取当前用户的规则总数
        total = await YaraRule.find(
            {"creator": {"$ref": "users", "$id": current_user.id}}
        ).count()
        
        # 获取当前用户的规则
        rules = await YaraRule.find(
            {"creator": {"$ref": "users", "$id": current_user.id}}
        ).skip(skip).limit(limit).to_list()
        
        # 构建响应列表
        response_list = []
        for rule in rules:
            creator = await rule.creator.fetch()
            response = YaraRuleResponse(
                id=str(rule.id),
                name=rule.name,
                description=rule.description,
                content=rule.content,
                creator=creator.username if creator else "Unknown",
                created_at=rule.created_at,
                updated_at=rule.updated_at,
                is_active=rule.is_active,
                is_public=rule.is_public,
                tags=rule.tags,
                metadata=rule.metadata
            )
            response_list.append(response)
        
        return {"data": response_list}
    except Exception as e:
        logger.error(f"获取规则列表失败: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"获取规则列表失败: {str(e)}"
        )

@router.get("/rules/{rule_id}", response_model=YaraRuleResponse)
async def get_rule(
    rule_id: str,
    current_user: User = Depends(get_current_user)
):
    """获取特定Yara规则，只允许查看自己创建的规则"""
    rule = await YaraRule.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")
    
    # 获取creator对象并检查权限
    creator = await rule.creator.fetch()
    if str(creator.id) != str(current_user.id):
        raise HTTPException(status_code=403, detail="没有权限查看此规则")
    
    return YaraRuleResponse(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        content=rule.content,
        creator=str(creator.id) if creator else None,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
        is_active=rule.is_active,
        is_public=rule.is_public,
        tags=rule.tags,
        metadata=rule.metadata
    )

@router.put("/rules/{rule_id}", response_model=YaraRuleResponse)
async def update_rule(
    rule_id: str,
    rule_update: YaraRuleUpdate,
    current_user: User = Depends(get_current_user)
):
    """更新Yara规则，只允许修改自己创建的规则"""
    rule = await YaraRule.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")
    
    # 获取creator对象并检查权限
    creator = await rule.creator.fetch()
    if str(creator.id) != str(current_user.id):
        raise HTTPException(status_code=403, detail="没有权限修改此规则")
    
    update_data = rule_update.dict(exclude_unset=True)
    
    # 如果更新了规则内容，验证新规则的语法
    if "content" in update_data:
        is_valid, error = await YaraManager.validate_rule(update_data["content"])
        if not is_valid:
            raise HTTPException(status_code=400, detail=f"规则语法错误: {error}")
    
    # 如果更新了规则名称，检查是否与其他规则重名
    if "name" in update_data:
        existing_rule = await YaraRule.find_one({"name": update_data["name"], "_id": {"$ne": rule.id}})
        if existing_rule:
            raise HTTPException(status_code=400, detail="规则名称已存在")
    
    # 更新时间戳
    update_data["updated_at"] = datetime.utcnow()
    
    # 更新规则
    await rule.update({"$set": update_data})
    
    # 重新获取更新后的规则
    updated_rule = await YaraRule.get(rule_id)
    creator = await updated_rule.creator.fetch()
    
    return YaraRuleResponse(
        id=str(updated_rule.id),
        name=updated_rule.name,
        description=updated_rule.description,
        content=updated_rule.content,
        creator=str(creator.id) if creator else None,
        created_at=updated_rule.created_at,
        updated_at=updated_rule.updated_at,
        is_active=updated_rule.is_active,
        is_public=updated_rule.is_public,
        tags=updated_rule.tags,
        metadata=updated_rule.metadata
    )

@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: str,
    current_user: User = Depends(get_current_user)
):
    """删除Yara规则，只允许删除自己创建的规则"""
    rule = await YaraRule.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")
    
    # 获取creator对象并检查权限
    creator = await rule.creator.fetch()
    if str(creator.id) != str(current_user.id):
        raise HTTPException(status_code=403, detail="没有权限删除此规则")
    
    await rule.delete()
    return {"message": "规则已删除"} 