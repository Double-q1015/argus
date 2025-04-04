import os
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MySQL数据库连接
SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{settings.MYSQL_USER}:{settings.MYSQL_PASSWORD}@{settings.MYSQL_HOST}:{settings.MYSQL_PORT}/{settings.MYSQL_DB}"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

async def init_db():
    """
    初始化数据库连接
    """
    try:
        # 初始化MySQL数据库
        with engine.connect() as conn:
            # 读取并执行迁移文件
            migrations_dir = os.path.join(os.path.dirname(__file__), "migrations")
            for filename in sorted(os.listdir(migrations_dir)):
                if filename.endswith(".sql"):
                    file_path = os.path.join(migrations_dir, filename)
                    logger.info(f"Executing migration: {filename}")
                    with open(file_path, "r", encoding="utf-8") as f:
                        sql_commands = f.read().split(";")
                        for command in sql_commands:
                            if command.strip():
                                try:
                                    conn.execute(text(command))
                                    conn.commit()
                                except Exception as e:
                                    logger.error(f"Error executing SQL command: {str(e)}")
                                    raise
        logger.info("MySQL database initialized successfully")
        
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise

async def close_db():
    """
    关闭数据库连接
    """
    try:
        engine.dispose()
        logger.info("MySQL database connection closed")
    except Exception as e:
        logger.error(f"Error closing database connection: {str(e)}")
        raise

if __name__ == "__main__":
    init_db() 