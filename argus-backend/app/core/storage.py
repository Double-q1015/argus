from minio import Minio
from minio.error import S3Error
from app.core.config import settings
from fastapi import UploadFile
import time
from datetime import timedelta
from typing import Optional, Union
import logging
import io
import os
import zipfile
import tempfile

logger = logging.getLogger(__name__)

def create_minio_client():
    """
    创建 MinIO 客户端
    """
    return Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE
    )

# 创建 MinIO 客户端
minio_client = create_minio_client()

class Storage:
    def __init__(self):
        self.client = Minio(
            endpoint=settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_SECURE
        )
        self.bucket_name = settings.MINIO_BUCKET_NAME
        self._ensure_bucket_exists()

    def _ensure_bucket_exists(self):
        """确保存储桶存在"""
        if not self.client.bucket_exists(self.bucket_name):
            self.client.make_bucket(self.bucket_name)
            logger.info(f"Created bucket: {self.bucket_name}")

    async def save_file(self, file_path: str, file: Union[UploadFile, bytes]) -> bool:
        """保存文件到存储"""
        try:
            # 确保存储桶存在
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(self.bucket_name)
                logger.info(f"Created bucket: {self.bucket_name}")

            # 根据文件类型处理
            if isinstance(file, bytes):
                file_data = file
                file_size = len(file)
                content_type = 'application/octet-stream'
            else:
                file_data = await file.read()
                file_size = len(file_data)
                content_type = file.content_type or 'application/octet-stream'

            # 检查文件大小
            if file_size == 0:
                logger.error(f"Empty file detected: {file_path}")
                return False

            # 使用异步方式上传文件
            try:
                self.client.put_object(
                    bucket_name=self.bucket_name,
                    object_name=file_path,
                    data=io.BytesIO(file_data),
                    length=file_size,
                    content_type=content_type
                )
                logger.info(f"Successfully saved file: {file_path}")
                return True
            except Exception as upload_error:
                logger.error(f"Failed to upload file {file_path}: {upload_error}")
                return False

        except Exception as e:
            logger.error(f"Error in save_file: {e}")
            return False

    async def delete_file(self, file_path: str) -> bool:
        """从存储中删除文件"""
        try:
            self.client.remove_object(self.bucket_name, file_path)
            return True
        except Exception as e:
            print(f"Error deleting file: {e}")
            return False

    async def get_file(self, file_path: str) -> Optional[bytes]:
        """从存储中获取文件内容"""
        try:
            response = self.client.get_object(self.bucket_name, file_path)
            return response.read()
        except Exception as e:
            print(f"Error getting file: {e}")
            return None

    async def get_presigned_url(self, file_path: str) -> Optional[str]:
        """获取文件的预签名URL"""
        try:
            logger.info(f"Generating presigned URL for: {file_path}")
            url = self.client.presigned_get_object(
                bucket_name=self.bucket_name,
                object_name=file_path,
                expires=timedelta(hours=1)
            )
            logger.info(f"Generated presigned URL for: {file_path}")
            return url
        except S3Error as e:
            logger.error(f"Error generating presigned URL: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error generating presigned URL: {e}")
            return None

    async def file_exists(self, file_path: str) -> bool:
        """检查文件是否存在"""
        try:
            logger.info(f"Checking if file exists: {file_path} in bucket: {self.bucket_name}")
            self.client.stat_object(self.bucket_name, file_path)
            logger.info(f"File exists: {file_path}")
            return True
        except S3Error as e:
            logger.error(f"Error checking file existence: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error checking file existence: {e}")
            return False

    async def create_encrypted_zip(self, file_path: str, password: str) -> Optional[str]:
        """创建加密的ZIP文件"""
        try:
            # 获取原始文件内容
            file_content = await self.get_file(file_path)
            if not file_content:
                logger.error(f"Failed to get file content for: {file_path}")
                return None

            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                # 创建ZIP文件
                zip_path = os.path.join(temp_dir, "encrypted.zip")
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    # 设置密码
                    zipf.setpassword(password.encode())
                    # 添加文件
                    zipf.writestr(os.path.basename(file_path), file_content)

                # 读取ZIP文件内容
                with open(zip_path, 'rb') as f:
                    zip_content = f.read()

                # 保存ZIP文件
                zip_file_path = f"{file_path}.zip"
                if await self.save_file(zip_file_path, zip_content):
                    logger.info(f"Successfully created encrypted ZIP file: {zip_file_path}")
                    return zip_file_path
                else:
                    logger.error(f"Failed to save encrypted ZIP file: {zip_file_path}")
                    return None

        except Exception as e:
            logger.error(f"Error creating encrypted ZIP file: {str(e)}")
            return None

    async def get_download_url(self, file_path: str) -> Optional[str]:
        """获取文件的下载URL"""
        try:
            # 生成预签名URL
            url = await self.client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': self.bucket_name,
                    'Key': file_path
                },
                ExpiresIn=3600  # URL有效期1小时
            )
            return url
        except Exception as e:
            logger.error(f"Error generating download URL: {str(e)}")
            return None

# 创建存储实例
storage = Storage()

async def get_sample(file_path: str):
    """
    获取样本文件
    """
    try:
        return await storage.get_file(file_path)
    except Exception as e:
        print(f"Error getting sample: {e}")
        return None

async def upload_sample(file_content: bytes, object_name: str, content_type: str) -> bool:
    """
    上传样本文件
    """
    try:
        storage.client.put_object(
            storage.bucket_name,
            f"samples/{object_name}",
            file_content,
            len(file_content),
            content_type=content_type
        )
        return True
    except Exception as e:
        print(f"Error uploading sample: {e}")
        return False

async def delete_sample(object_name: str) -> bool:
    """
    删除样本文件
    """
    try:
        storage.client.remove_object(storage.bucket_name, f"samples/{object_name}")
        return True
    except Exception as e:
        print(f"Error deleting sample: {e}")
        return False

async def init_storage():
    """
    初始化存储系统
    """
    max_retries = 3
    retry_delay = 2  # 秒
    
    for attempt in range(max_retries):
        try:
            # 确保存储桶存在
            if not minio_client.bucket_exists(settings.MINIO_BUCKET_NAME):
                print(f"Creating bucket: {settings.MINIO_BUCKET_NAME}")
                minio_client.make_bucket(settings.MINIO_BUCKET_NAME)
                print(f"Bucket created successfully: {settings.MINIO_BUCKET_NAME}")
            return True
        except S3Error as e:
            print(f"Attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print("Failed to initialize storage after all retries")
                raise 