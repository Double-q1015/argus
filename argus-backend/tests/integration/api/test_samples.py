import os
import asyncio
import aiohttp
from tqdm import tqdm
import logging
from typing import Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 配置
SAMPLE_DIR = "/data/Virusshare.00481"
API_BASE_URL = "http://localhost:8000/api/v1"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin123!@#"

async def get_access_token(session: aiohttp.ClientSession) -> Optional[str]:
    """获取访问令牌"""
    try:
        logger.info(f"正在使用用户名 {ADMIN_USERNAME} 获取访问令牌")
        
        # 使用 OAuth2 密码模式的表单数据
        data = {
            'username': ADMIN_USERNAME,
            'password': ADMIN_PASSWORD,
            'grant_type': 'password'
        }
        
        async with session.post(
            f"{API_BASE_URL}/auth/token",
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        ) as response:
            if response.status == 200:
                data = await response.json()
                logger.info("成功获取访问令牌")
                return data.get("access_token")
            else:
                error_text = await response.text()
                logger.error(f"获取访问令牌失败: {response.status}, 错误: {error_text}")
                return None
    except Exception as e:
        logger.error(f"获取访问令牌时发生错误: {e}")
        return None

async def get_sample_baseinfo(sha256_digest: str, access_token: str, session: aiohttp.ClientSession) -> bool:
    """获取样本基本信息"""
    try:
       headers = {'Authorization': f'Bearer {access_token}'}
       async with session.get(f"{API_BASE_URL}/samples/{sha256_digest}/baseinfo", headers=headers) as response:
           print(response.status)
           if response.status == 200:
               data = await response.json()
               print(data)
    except Exception as e:
        logger.error(f"获取样本基本信息时发生错误: {str(e)}")
        return False

async def main():
    sha256_digest = "69d9062b30ddf23eadc129496f5b30a2ac19ff83b2e55148eb6d2a6f96c61e2c"
    # 创建会话并获取访问令牌
    async with aiohttp.ClientSession() as session:
        access_token = await get_access_token(session)
        print(f"access_token: {access_token}")
        data = await get_sample_baseinfo(sha256_digest, access_token, session)

if __name__ == "__main__":
    asyncio.run(main()) 