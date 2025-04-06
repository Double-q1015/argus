from typing import List, Union, Optional, Dict, Any
from pydantic import BaseSettings, validator
import os
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler

load_dotenv()

class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Snake Skin"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Snake Skin API"
    
    # CORS配置
    BACKEND_CORS_ORIGINS: List[str] = []

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # JWT配置
    SECRET_KEY: str = "your-secret-key-here"  # 在生产环境中应该使用环境变量
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # MySQL数据库配置
    MYSQL_USER: str = os.getenv("MYSQL_USER", "doinb")
    MYSQL_PASSWORD: str = os.getenv("MYSQL_PASSWORD", "doinb")
    MYSQL_HOST: str = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_PORT: str = os.getenv("MYSQL_PORT", "3306")
    MYSQL_DB: str = os.getenv("MYSQL_DB", "snake_skin")

    @property
    def SQLALCHEMY_DATABASE_URL(self) -> str:
        return f"mysql+pymysql://{self.MYSQL_USER}:{self.MYSQL_PASSWORD}@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DB}"

    # MongoDB配置
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "snake_skin"

    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS: List[str] = ["jpg", "jpeg", "png", "gif"]

    # MinIO配置
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_BUCKET_NAME: str = "samples"
    MINIO_SECURE: bool = False
    
    # 压缩配置
    COMPRESSION_PASSWORD: str = "infected"
    
    # 日志配置
    LOG_DIR: str = "logs"
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5

    # AWS S3配置
    S3_ENDPOINT: Optional[str] = None
    S3_ACCESS_KEY: Optional[str] = None
    S3_SECRET_KEY: Optional[str] = None
    S3_REGION: str = "us-east-1"
    S3_BUCKET_NAME: Optional[str] = None
    S3_SECURE: bool = True
    
    # 本地文件存储配置
    LOCAL_STORAGE_PATH: str = "/data/argus-samples"
    
    # 存储配置
    STORAGE_TYPE: str = "minio"  # 可选值: "minio", "s3", "local"
    
    @property
    def storage_config(self) -> Dict[str, Any]:
        """获取存储配置"""
        if self.STORAGE_TYPE == "minio":
            return {
                "endpoint": self.MINIO_ENDPOINT,
                "access_key": self.MINIO_ACCESS_KEY,
                "secret_key": self.MINIO_SECRET_KEY,
                "secure": self.MINIO_SECURE,
                "bucket_name": self.MINIO_BUCKET_NAME
            }
        elif self.STORAGE_TYPE == "s3":
            if not all([self.S3_ACCESS_KEY, self.S3_SECRET_KEY, self.S3_BUCKET_NAME]):
                raise ValueError("S3 configuration is incomplete")
            return {
                "endpoint": self.S3_ENDPOINT,
                "access_key": self.S3_ACCESS_KEY,
                "secret_key": self.S3_SECRET_KEY,
                "region": self.S3_REGION,
                "bucket_name": self.S3_BUCKET_NAME,
                "secure": self.S3_SECURE
            }
        elif self.STORAGE_TYPE == "local":
            return {
                "base_path": self.LOCAL_STORAGE_PATH
            }
        else:
            raise ValueError(f"Unsupported storage type: {self.STORAGE_TYPE}")

    def setup_logging(self):
        """配置日志系统"""
        # 创建日志目录
        if not os.path.exists(self.LOG_DIR):
            os.makedirs(self.LOG_DIR)
        
        # 配置根日志记录器
        root_logger = logging.getLogger()
        root_logger.setLevel(self.LOG_LEVEL)
        
        # 创建文件处理器
        file_handler = RotatingFileHandler(
            os.path.join(self.LOG_DIR, "app.log"),
            maxBytes=self.LOG_MAX_BYTES,
            backupCount=self.LOG_BACKUP_COUNT,
            encoding='utf-8'
        )
        file_handler.setFormatter(logging.Formatter(self.LOG_FORMAT))
        
        # 创建控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(self.LOG_FORMAT))
        
        # 添加处理器
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
settings.setup_logging()  # 初始化时设置日志 