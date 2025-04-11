from fastapi import APIRouter, Depends
from app.models.user import User
from app.core.security import get_current_user

router = APIRouter()

@router.get("/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    """
    获取当前用户信息
    """
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "email": current_user.email,
        "is_active": current_user.is_active,
        "is_superuser": current_user.is_superuser,
        "last_login": current_user.last_login
    } 