#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import logging
import asyncio
import boto3
from botocore.config import Config
from app.core.config import settings
from datetime import datetime, timedelta

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
logger.info(f"Project root: {project_root}")

def get_bucket_stats(bucket_name):
    """
    使用 boto3 获取指定存储桶的统计信息
    
    Args:
        bucket_name: 存储桶名称
        
    Returns:
        dict: 存储桶统计信息
    """
    try:
        # 创建 S3 客户端
        s3_client = boto3.client(
            's3',
            endpoint_url=f"{'https' if settings.MINIO_SECURE else 'http'}://{settings.MINIO_ENDPOINT}",
            aws_access_key_id=settings.MINIO_ACCESS_KEY,
            aws_secret_access_key=settings.MINIO_SECRET_KEY,
            config=Config(signature_version='s3v4'),
            region_name='us-east-1'  # MinIO 默认区域
        )
        
        # 检查存储桶是否存在
        try:
            s3_client.head_bucket(Bucket=bucket_name)
        except Exception as e:
            logger.error(f"存储桶 {bucket_name} 不存在或无法访问: {str(e)}")
            return None
        
        # 获取存储桶统计信息
        stats = {}
        
        # 获取存储桶 ACL
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            stats['acl'] = acl
        except Exception as e:
            logger.error(f"获取存储桶 ACL 时出错: {str(e)}")
        
        # 获取存储桶策略
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            stats['policy'] = policy
        except Exception as e:
            logger.error(f"获取存储桶策略时出错: {str(e)}")
        
        # 获取存储桶版本控制状态
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            stats['versioning'] = versioning
        except Exception as e:
            logger.error(f"获取存储桶版本控制状态时出错: {str(e)}")
        
        # 获取存储桶生命周期规则
        try:
            lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            stats['lifecycle'] = lifecycle
        except Exception as e:
            logger.error(f"获取存储桶生命周期规则时出错: {str(e)}")
        
        # 获取存储桶标签
        try:
            tags = s3_client.get_bucket_tagging(Bucket=bucket_name)
            stats['tags'] = tags
        except Exception as e:
            logger.error(f"获取存储桶标签时出错: {str(e)}")
        
        # 获取存储桶加密配置
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            stats['encryption'] = encryption
        except Exception as e:
            logger.error(f"获取存储桶加密配置时出错: {str(e)}")
        
        # 获取存储桶对象数量和总大小
        try:
            # 使用 list_objects_v2 获取对象列表
            paginator = s3_client.get_paginator('list_objects_v2')
            count = 0
            total_size = 0
            
            for page in paginator.paginate(Bucket=bucket_name):
                if 'Contents' in page:
                    for obj in page['Contents']:
                        count += 1
                        total_size += obj['Size']
            
            stats['object_count'] = count
            stats['total_size'] = total_size
        except Exception as e:
            logger.error(f"获取存储桶对象统计时出错: {str(e)}")
        
        return stats
    
    except Exception as e:
        logger.error(f"获取存储桶统计信息时出错: {str(e)}")
        return None

def format_size(size_bytes):
    """
    将字节大小格式化为人类可读的格式
    
    Args:
        size_bytes: 字节大小
        
    Returns:
        str: 格式化后的大小
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    elif size_bytes < 1024 * 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024 * 1024):.2f} TB"

async def main():
    """主函数"""
    # 获取命令行参数中的存储桶名称，如果没有则使用默认值
    bucket_name = settings.MINIO_BUCKET_NAME
    if len(sys.argv) > 1:
        bucket_name = sys.argv[1]
    
    logger.info(f"开始获取存储桶 {bucket_name} 的统计信息...")
    
    # 获取存储桶统计信息
    stats = get_bucket_stats(bucket_name)
    
    if not stats:
        logger.error("无法获取存储桶统计信息")
        return
    
    # 输出结果
    logger.info(f"存储桶: {bucket_name}")
    
    if 'object_count' in stats:
        logger.info(f"对象数量: {stats['object_count']}")
    
    if 'total_size' in stats:
        logger.info(f"总大小: {format_size(stats['total_size'])}")
    
    if 'versioning' in stats:
        logger.info(f"版本控制状态: {stats['versioning'].get('Status', '未启用')}")
    
    if 'lifecycle' in stats:
        logger.info(f"生命周期规则: {stats['lifecycle']}")
    
    if 'tags' in stats:
        logger.info(f"标签: {stats['tags']}")
    
    if 'encryption' in stats:
        logger.info(f"加密配置: {stats['encryption']}")
    
    # 尝试获取存储桶指标（仅适用于 AWS S3，MinIO 可能不支持）
    try:
        s3_client = boto3.client(
            's3',
            endpoint_url=f"{'https' if settings.MINIO_SECURE else 'http'}://{settings.MINIO_ENDPOINT}",
            aws_access_key_id=settings.MINIO_ACCESS_KEY,
            aws_secret_access_key=settings.MINIO_SECRET_KEY,
            config=Config(signature_version='s3v4'),
            region_name='us-east-1'
        )
        
        # 尝试获取存储桶指标
        metrics = s3_client.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='BucketSizeBytes',
            Dimensions=[{'Name': 'BucketName', 'Value': bucket_name}],
            StartTime=datetime.now() - timedelta(days=1),
            EndTime=datetime.now(),
            Period=86400,
            Statistics=['Average']
        )
        
        if metrics and 'Datapoints' in metrics and metrics['Datapoints']:
            logger.info(f"存储桶指标: {metrics}")
    except Exception as e:
        logger.error(f"获取存储桶指标时出错: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main()) 