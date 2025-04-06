from abc import ABC, abstractmethod
from minio import Minio
from minio.error import S3Error
from app.core.config import settings
from fastapi import UploadFile
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Dict, Any, List
import logging
import io
import os
import zipfile
import tempfile
import boto3
from botocore.exceptions import ClientError
import shutil
from pathlib import Path
import itertools

logger = logging.getLogger(__name__)

class StorageAdapter(ABC):
    """存储适配器接口"""
    
    @abstractmethod
    async def save_file(self, file_path: str, file: Union[UploadFile, bytes]) -> bool:
        """保存文件到存储"""
        pass
    
    @abstractmethod
    async def delete_file(self, file_path: str) -> bool:
        """从存储中删除文件"""
        pass
    
    @abstractmethod
    async def get_file(self, file_path: str) -> Optional[bytes]:
        """从存储中获取文件内容"""
        pass
    
    @abstractmethod
    async def get_presigned_url(self, file_path: str) -> Optional[str]:
        """获取文件的预签名URL"""
        pass
    
    @abstractmethod
    async def file_exists(self, file_path: str) -> bool:
        """检查文件是否存在"""
        pass
    
    @abstractmethod
    async def get_file_stat(self, file_path: str) -> Optional[Dict[str, Any]]:
        """获取文件状态信息"""
        pass
        
    @abstractmethod
    async def list_files(self, prefix: str = "", recursive: bool = True) -> List[Dict[str, Any]]:
        """列出存储中的文件
        
        Args:
            prefix: 文件前缀，用于过滤文件
            recursive: 是否递归列出子目录中的文件
            
        Returns:
            文件信息列表，每个文件信息包含以下字段：
            - path: 文件路径
            - size: 文件大小（字节）
            - last_modified: 最后修改时间
            - is_dir: 是否为目录
        """
        pass

    @abstractmethod
    async def list_files_with_pagination(
        self,
        prefix: str = "",
        delimiter: str = "",
        max_keys: int = 1000,
        start_after: str = None
    ) -> Dict[str, Any]:
        """
        分页列出文件
        :param prefix: 前缀过滤
        :param delimiter: 分隔符
        :param max_keys: 每页最大数量
        :param start_after: 从哪个文件开始（用于分页）
        :return: 包含文件列表和下一页标记的字典
        """
        pass

class LocalStorageAdapter(StorageAdapter):
    """本地文件存储适配器"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化本地存储适配器
        :param config: 配置信息，包含base_path和directory_depth
        """
        self.base_path = config["base_path"]
        # 新增配置：目录层级深度，默认为0（不分层）
        directory_depth = config.get("directory_depth", 0)
        if not isinstance(directory_depth, int) or directory_depth < 0 or directory_depth > 4:
            logger.warning(f"无效的目录层级深度: {directory_depth}，将使用默认值0")
            directory_depth = 0
        self.directory_depth = directory_depth
        os.makedirs(self.base_path, exist_ok=True)
        
    def _get_file_path(self, file_path: str) -> str:
        """
        根据配置的目录层级深度生成实际的文件路径
        :param file_path: 原始文件路径（通常是SHA256值）
        :return: 实际的文件路径
        """
        if self.directory_depth <= 0:
            return os.path.join(self.base_path, file_path)
            
        # 假设file_path是SHA256值
        if len(file_path) < self.directory_depth:
            logger.warning(f"文件路径 {file_path} 长度小于目录层级深度 {self.directory_depth}，将不进行分层")
            return os.path.join(self.base_path, file_path)
            
        # 创建分层目录
        dir_path = os.path.join(self.base_path, *[file_path[i] for i in range(self.directory_depth)])
        os.makedirs(dir_path, exist_ok=True)
        return os.path.join(dir_path, file_path)
        
    async def save_file(self, file_path: str, file: Union[UploadFile, bytes]) -> bool:
        """保存文件"""
        try:
            # 使用_get_file_path获取实际的文件路径
            actual_path = self._get_file_path(file_path)
            
            # 确保目录存在
            os.makedirs(os.path.dirname(actual_path), exist_ok=True)
            
            if isinstance(file, bytes):
                file_data = file
            else:
                file_data = await file.read()
            
            if len(file_data) == 0:
                logger.error(f"Empty file detected: {file_path}")
                return False
            
            # 保存文件
            with open(actual_path, "wb") as f:
                f.write(file_data)
            logger.info(f"Successfully saved file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"保存文件失败: {str(e)}")
            return False
            
    async def delete_file(self, file_path: str) -> bool:
        """删除文件"""
        try:
            actual_path = self._get_file_path(file_path)
            if os.path.exists(actual_path):
                os.remove(actual_path)
            logger.info(f"Successfully deleted file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"删除文件失败: {str(e)}")
            return False
            
    async def get_file(self, file_path: str) -> Optional[bytes]:
        """获取文件内容"""
        try:
            actual_path = self._get_file_path(file_path)
            if not os.path.exists(actual_path):
                logger.error(f"File not found: {file_path}")
                return None
            with open(actual_path, "rb") as f:
                return f.read()
        except Exception as e:
            logger.error(f"获取文件失败: {str(e)}")
            return None
            
    async def get_presigned_url(self, file_path: str) -> Optional[str]:
        """获取预签名URL（本地存储不支持）"""
        return None
        
    async def file_exists(self, file_path: str) -> bool:
        """检查文件是否存在"""
        try:
            actual_path = self._get_file_path(file_path)
            return os.path.exists(actual_path)
        except Exception as e:
            logger.error(f"检查文件是否存在失败: {str(e)}")
            return False
            
    async def get_file_stat(self, file_path: str) -> Optional[Dict[str, Any]]:
        """获取文件状态信息"""
        try:
            actual_path = self._get_file_path(file_path)
            if not os.path.exists(actual_path):
                return None
            stat = os.stat(actual_path)
            return {
                "size": stat.st_size,
                "last_modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc)
            }
        except Exception as e:
            logger.error(f"获取文件状态失败: {str(e)}")
            return None
            
    async def list_files(self, prefix: str = "", recursive: bool = True) -> List[Dict[str, Any]]:
        """列出所有文件"""
        try:
            files = []
            for root, _, filenames in os.walk(self.base_path):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, self.base_path)
                    files.append({
                        "path": rel_path,
                        "size": os.path.getsize(file_path),
                        "last_modified": datetime.fromtimestamp(
                            os.path.getmtime(file_path),
                            timezone.utc
                        )
                    })
            return files
        except Exception as e:
            logger.error(f"列出文件失败: {str(e)}")
            return []
            
    async def list_files_with_pagination(
        self,
        prefix: str = "",
        delimiter: str = "",
        max_keys: int = 1000,
        start_after: str = None
    ) -> Dict[str, Any]:
        """
        分页列出文件
        :param prefix: 前缀过滤
        :param delimiter: 分隔符
        :param max_keys: 每页最大数量
        :param start_after: 从哪个文件开始（用于分页）
        :return: 包含文件列表和下一页标记的字典
        """
        try:
            files = []
            count = 0
            start_found = start_after is None
            
            for root, _, filenames in os.walk(self.base_path):
                for filename in filenames:
                    if count >= max_keys:
                        break
                        
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, self.base_path)
                    
                    if not start_found:
                        if rel_path == start_after:
                            start_found = True
                        continue
                        
                    if prefix and not rel_path.startswith(prefix):
                        continue
                        
                    files.append({
                        "path": rel_path,
                        "size": os.path.getsize(file_path),
                        "last_modified": datetime.fromtimestamp(
                            os.path.getmtime(file_path),
                            timezone.utc
                        )
                    })
                    count += 1
                    
            return {
                "files": files,
                "is_truncated": count >= max_keys,
                "next_marker": files[-1]["path"] if files else None
            }
        except Exception as e:
            logger.error(f"列出文件失败: {str(e)}")
            raise

class MinioStorageAdapter(StorageAdapter):
    """MinIO存储适配器"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化MinIO存储适配器
        :param config: 配置信息，包含endpoint、access_key、secret_key、secure等
        """
        self.client = Minio(
            config["endpoint"],
            access_key=config["access_key"],
            secret_key=config["secret_key"],
            secure=config.get("secure", False)
        )
        self.bucket_name = config["bucket_name"]
        self._ensure_bucket_exists()
    
    def _ensure_bucket_exists(self):
        """确保存储桶存在"""
        if not self.client.bucket_exists(self.bucket_name):
            self.client.make_bucket(self.bucket_name)
            logger.info(f"Created bucket: {self.bucket_name}")
    
    async def save_file(self, file_path: str, file: Union[UploadFile, bytes]) -> bool:
        try:
            if isinstance(file, bytes):
                file_data = file
                file_size = len(file)
                content_type = 'application/octet-stream'
            else:
                file_data = await file.read()
                file_size = len(file_data)
                content_type = file.content_type or 'application/octet-stream'
            
            if file_size == 0:
                logger.error(f"Empty file detected: {file_path}")
                return False
            
            self.client.put_object(
                bucket_name=self.bucket_name,
                object_name=file_path,
                data=io.BytesIO(file_data),
                length=file_size,
                content_type=content_type
            )
            logger.info(f"Successfully saved file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error in save_file: {e}")
            return False
    
    async def delete_file(self, file_path: str) -> bool:
        try:
            self.client.remove_object(self.bucket_name, file_path)
            return True
        except Exception as e:
            logger.error(f"Error deleting file: {e}")
            return False
    
    async def get_file(self, file_path: str) -> Optional[bytes]:
        try:
            response = self.client.get_object(self.bucket_name, file_path)
            return response.read()
        except Exception as e:
            logger.error(f"Error getting file: {e}")
            return None
    
    async def get_presigned_url(self, file_path: str) -> Optional[str]:
        try:
            url = self.client.presigned_get_object(
                bucket_name=self.bucket_name,
                object_name=file_path,
                expires=timedelta(hours=1)
            )
            return url
        except Exception as e:
            logger.error(f"Error generating presigned URL: {e}")
            return None
    
    async def file_exists(self, file_path: str) -> bool:
        try:
            self.client.stat_object(self.bucket_name, file_path)
            return True
        except Exception as e:
            logger.error(f"Error checking file existence: {e}")
            return False
    
    async def get_file_stat(self, file_path: str) -> Optional[Dict[str, Any]]:
        try:
            stat = self.client.stat_object(self.bucket_name, file_path)
            return {
                "size": stat.size,
                "last_modified": stat.last_modified,
                "etag": stat.etag,
                "content_type": stat.content_type
            }
        except Exception as e:
            logger.error(f"Error getting file stat: {e}")
            return None
            
    async def list_files(self, prefix: str = "", recursive: bool = True) -> List[Dict[str, Any]]:
        """列出MinIO存储中的文件"""
        try:
            result = []
            
            # 设置递归参数
            recursive_param = recursive
            
            # 列出对象
            objects = self.client.list_objects(
                bucket_name=self.bucket_name,
                prefix=prefix,
                recursive=recursive_param
            )
            
            # 处理结果
            for obj in objects:
                result.append({
                    "path": obj.object_name,
                    "size": obj.size,
                    "last_modified": obj.last_modified,
                    "is_dir": obj.is_dir
                })
            
            return result
        except Exception as e:
            logger.error(f"Error listing files: {e}")
            return []

    async def list_files_with_pagination(
        self,
        prefix: str = "",
        delimiter: str = "",
        max_keys: int = 1000,
        start_after: str = None
    ) -> Dict[str, Any]:
        """
        分页列出文件
        :param prefix: 前缀过滤
        :param delimiter: 分隔符（MinIO不支持此参数）
        :param max_keys: 每页最大数量
        :param start_after: 从哪个文件开始（用于分页）
        :return: 包含文件列表和下一页标记的字典
        """
        try:
            # 使用MinIO的list_objects方法，它支持分页
            objects = self.client.list_objects(
                self.bucket_name,
                prefix=prefix,
                start_after=start_after,
                recursive=True
            )
            
            files = []
            count = 0
            
            # 只处理指定数量的文件
            for obj in objects:
                if count >= max_keys:
                    # 如果已经处理了足够的文件，就停止迭代
                    # 但不消耗迭代器，这样下次调用时可以从这里继续
                    break
                    
                files.append({
                    "path": obj.object_name,
                    "size": obj.size,
                    "last_modified": obj.last_modified
                })
                count += 1
                
            # 检查是否还有更多文件
            has_more = False
            try:
                # 尝试获取下一个对象，但不消耗它
                next_obj = next(objects)
                has_more = True
            except StopIteration:
                pass
                
            return {
                "files": files,
                "is_truncated": has_more,
                "next_marker": files[-1]["path"] if files else None
            }
        except Exception as e:
            logger.error(f"列出文件失败: {str(e)}")
            raise

class S3StorageAdapter(StorageAdapter):
    """AWS S3存储适配器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.client = boto3.client(
            's3',
            aws_access_key_id=config["access_key"],
            aws_secret_access_key=config["secret_key"],
            region_name=config.get("region", "us-east-1"),
            endpoint_url=config.get("endpoint")
        )
        self.bucket_name = config["bucket_name"]
        self._ensure_bucket_exists()
    
    def _ensure_bucket_exists(self):
        """确保存储桶存在"""
        try:
            self.client.head_bucket(Bucket=self.bucket_name)
        except ClientError:
            self.client.create_bucket(Bucket=self.bucket_name)
            logger.info(f"Created bucket: {self.bucket_name}")
    
    async def save_file(self, file_path: str, file: Union[UploadFile, bytes]) -> bool:
        try:
            if isinstance(file, bytes):
                file_data = file
                content_type = 'application/octet-stream'
            else:
                file_data = await file.read()
                content_type = file.content_type or 'application/octet-stream'
            
            if len(file_data) == 0:
                logger.error(f"Empty file detected: {file_path}")
                return False
            
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=file_path,
                Body=file_data,
                ContentType=content_type
            )
            logger.info(f"Successfully saved file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error in save_file: {e}")
            return False
    
    async def delete_file(self, file_path: str) -> bool:
        try:
            self.client.delete_object(Bucket=self.bucket_name, Key=file_path)
            return True
        except Exception as e:
            logger.error(f"Error deleting file: {e}")
            return False
    
    async def get_file(self, file_path: str) -> Optional[bytes]:
        try:
            response = self.client.get_object(Bucket=self.bucket_name, Key=file_path)
            return response['Body'].read()
        except Exception as e:
            logger.error(f"Error getting file: {e}")
            return None
    
    async def get_presigned_url(self, file_path: str) -> Optional[str]:
        try:
            url = self.client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': self.bucket_name,
                    'Key': file_path
                },
                ExpiresIn=3600
            )
            return url
        except Exception as e:
            logger.error(f"Error generating presigned URL: {e}")
            return None
    
    async def file_exists(self, file_path: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket_name, Key=file_path)
            return True
        except ClientError:
            return False
        except Exception as e:
            logger.error(f"Error checking file existence: {e}")
            return False
    
    async def get_file_stat(self, file_path: str) -> Optional[Dict[str, Any]]:
        try:
            response = self.client.head_object(Bucket=self.bucket_name, Key=file_path)
            return {
                "size": response['ContentLength'],
                "last_modified": response['LastModified'],
                "etag": response['ETag'].strip('"'),
                "content_type": response.get('ContentType', 'application/octet-stream')
            }
        except Exception as e:
            logger.error(f"Error getting file stat: {e}")
            return None
            
    async def list_files(self, prefix: str = "", recursive: bool = True) -> List[Dict[str, Any]]:
        """列出S3存储中的文件"""
        try:
            result = []
            
            # 设置分页参数
            paginator = self.client.get_paginator('list_objects_v2')
            
            # 设置请求参数
            params = {
                'Bucket': self.bucket_name,
                'Prefix': prefix
            }
            
            # 如果不递归，则只列出指定前缀下的文件
            if not recursive:
                # 获取前缀的最后一个部分
                parts = prefix.split('/')
                if parts:
                    last_part = parts[-1]
                    if last_part:
                        # 设置分隔符为最后一个部分
                        params['Delimiter'] = '/'
            
            # 遍历所有页面
            for page in paginator.paginate(**params):
                # 处理文件
                if 'Contents' in page:
                    for obj in page['Contents']:
                        result.append({
                            "path": obj['Key'],
                            "size": obj['Size'],
                            "last_modified": obj['LastModified'],
                            "is_dir": False
                        })
                
                # 处理目录（仅在不递归时）
                if not recursive and 'CommonPrefixes' in page:
                    for prefix_obj in page['CommonPrefixes']:
                        result.append({
                            "path": prefix_obj['Prefix'],
                            "size": 0,
                            "last_modified": None,
                            "is_dir": True
                        })
            
            return result
        except Exception as e:
            logger.error(f"Error listing files: {e}")
            return []

class StorageFactory:
    """存储适配器工厂"""
    
    @staticmethod
    def create_adapter(storage_type: str, config: Dict[str, Any]) -> StorageAdapter:
        """创建存储适配器"""
        if storage_type == "minio":
            return MinioStorageAdapter(config)
        elif storage_type == "s3":
            return S3StorageAdapter(config)
        elif storage_type == "local":
            return LocalStorageAdapter(config)
        else:
            raise ValueError(f"Unsupported storage type: {storage_type}")

# 创建默认的MinIO存储适配器
storage_adapter = StorageFactory.create_adapter(settings.STORAGE_TYPE, settings.storage_config)

# 为了向后兼容，保留原有的Storage类
class Storage:
    def __init__(self):
        self.adapter = storage_adapter
    
    async def save_file(self, file_path: str, file: Union[UploadFile, bytes]) -> bool:
        return await self.adapter.save_file(file_path, file)
    
    async def delete_file(self, file_path: str) -> bool:
        return await self.adapter.delete_file(file_path)
    
    async def get_file(self, file_path: str) -> Optional[bytes]:
        return await self.adapter.get_file(file_path)
    
    async def get_presigned_url(self, file_path: str) -> Optional[str]:
        return await self.adapter.get_presigned_url(file_path)
    
    async def file_exists(self, file_path: str) -> bool:
        return await self.adapter.file_exists(file_path)
    
    async def get_file_stat(self, file_path: str) -> Optional[Dict[str, Any]]:
        return await self.adapter.get_file_stat(file_path)
        
    async def list_files(self, prefix: str = "", recursive: bool = True) -> List[Dict[str, Any]]:
        return await self.adapter.list_files(prefix, recursive)

# 创建存储实例
storage = Storage()

async def init_storage():
    """初始化存储系统"""
    try:
        # 使用存储适配器初始化存储
        if await storage_adapter.file_exists("test.txt"):
            await storage_adapter.delete_file("test.txt")
        
        # 测试文件上传
        test_content = b"test"
        if await storage_adapter.save_file("test.txt", test_content):
            # 测试文件下载
            downloaded_content = await storage_adapter.get_file("test.txt")
            if downloaded_content == test_content:
                # 测试文件删除
                await storage_adapter.delete_file("test.txt")
                logger.info("Storage initialization successful")
                return True
        
        logger.error("Storage initialization failed")
        return False
    except Exception as e:
        logger.error(f"Error initializing storage: {e}")
        return False

async def upload_sample(file: UploadFile, file_path: str) -> bool:
    """
    上传样本文件到存储
    
    Args:
        file: 上传的文件
        file_path: 文件在存储中的路径
        
    Returns:
        bool: 上传是否成功
    """
    return await storage.save_file(file_path, file)

async def delete_sample(file_path: str) -> bool:
    """
    从存储中删除样本文件
    
    Args:
        file_path: 文件在存储中的路径
        
    Returns:
        bool: 删除是否成功
    """
    return await storage.delete_file(file_path)

async def get_sample(file_path: str) -> Optional[bytes]:
    """
    从存储中获取样本文件内容
    
    Args:
        file_path: 文件在存储中的路径
        
    Returns:
        Optional[bytes]: 文件内容，如果文件不存在则返回None
    """
    return await storage.get_file(file_path)

def create_minio_client() -> Minio:
    """
    创建MinIO客户端
    
    Returns:
        Minio: MinIO客户端实例
    """
    return Minio(
        endpoint=settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE
    ) 