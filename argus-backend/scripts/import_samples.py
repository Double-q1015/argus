import os
import asyncio
import aiohttp
from tqdm import tqdm
import logging
from typing import Optional
from app.core.config import settings

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
ADMIN_PASSWORD = "admin123"

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
            f"{API_BASE_URL}/auth/token",  # 使用新的 /token 端点
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

async def upload_sample(file_path: str, access_token: str) -> bool:
    """上传单个样本文件"""
    try:
        # 打开文件
        file = open(file_path, 'rb')
        try:
            # 准备表单数据
            form = aiohttp.FormData()
            form.add_field('file', file, filename=os.path.basename(file_path))
            form.add_field('tags', '[]')
            
            # 发送请求
            async with aiohttp.ClientSession() as session:
                headers = {'Authorization': f'Bearer {access_token}'}
                async with session.post(f'{API_BASE_URL}/samples/upload', data=form, headers=headers) as response:
                    if response.status == 200:
                        logger.info(f"文件上传成功: {file_path}")
                        return True
                    else:
                        response_text = await response.text()
                        logger.error(f"文件上传失败: {file_path}, 状态码: {response.status}, 响应: {response_text}")
                        return False
        finally:
            file.close()
            
    except Exception as e:
        logger.error(f"上传文件时发生错误: {file_path}, 错误: {str(e)}")
        return False

async def import_samples(sample_dir: str):
    """导入样本"""
    try:
        # 检查样本目录是否存在
        if not os.path.exists(sample_dir):
            logger.error(f"样本目录不存在: {sample_dir}")
            return
        
        # 创建会话并获取访问令牌
        async with aiohttp.ClientSession() as session:
            access_token = await get_access_token(session)
            if not access_token:
                logger.error("获取访问令牌失败")
                return
                
            # 获取目录下的所有文件
            files = []
            for root, _, filenames in os.walk(sample_dir):
                for filename in filenames:
                    files.append(os.path.join(root, filename))
            
            total_files = len(files)
            success_count = 0
            
            # 使用tqdm显示进度
            for i, file_path in enumerate(tqdm(files), 1):
                file_name = os.path.basename(file_path)
                logger.info(f"正在处理第 {i}/{total_files} 个文件: {file_name}")
                
                if await upload_sample(file_path, access_token):
                    success_count += 1
                else:
                    logger.error(f"文件上传失败: {file_name}")
                
                # 添加短暂延迟避免请求过快
                await asyncio.sleep(0.1)
            
            logger.info(f"导入完成! 成功: {success_count}/{total_files}")
        
    except Exception as e:
        logger.error(f"导入样本时发生错误: {str(e)}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(import_samples(SAMPLE_DIR)) 