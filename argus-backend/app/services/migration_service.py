import logging
import asyncio
import fnmatch
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Tuple
from beanie import PydanticObjectId
from app.models.migration import MigrationTask, MigrationFileStatus, MigrationStatus
from app.core.storage import StorageFactory, StorageAdapter, MinioStorageAdapter
from app.core.config import settings
from collections import defaultdict

logger = logging.getLogger(__name__)


class MigrationService:
    """迁移服务"""

    @staticmethod
    async def create_migration_task(
        name: str,
        source_storage: str,
        source_config: Dict[str, Any],
        target_storage: str,
        target_config: Dict[str, Any],
        description: Optional[str] = None,
        file_patterns: Optional[List[str]] = None
    ) -> MigrationTask:
        """创建迁移任务"""
        task = MigrationTask(
            name=name,
            description=description,
            source_storage=source_storage,
            source_config=source_config,
            target_storage=target_storage,
            target_config=target_config,
            file_patterns=file_patterns
        )
        await task.insert()
        logger.info(f"Created migration task: {task.id}")
        return task

    @staticmethod
    async def get_migration_task(task_id: str) -> Optional[MigrationTask]:
        """获取迁移任务"""
        return await MigrationTask.get(PydanticObjectId(task_id))

    @staticmethod
    async def get_migration_tasks(
        skip: int = 0,
        limit: int = 100,
        status: Optional[MigrationStatus] = None
    ) -> List[Dict[str, Any]]:
        """获取迁移任务列表"""
        query = {}
        if status:
            query["status"] = status
        logger.info(f"Getting migration tasks with query: {query}, skip: {skip}, limit: {limit}")
        tasks = await MigrationTask.find(query).skip(skip).limit(limit).to_list()
        logger.info(f"Found {len(tasks)} migration tasks")
        return [task.to_dict() for task in tasks]

    @staticmethod
    async def count_migration_tasks(
        status: Optional[MigrationStatus] = None
    ) -> int:
        """获取迁移任务总数"""
        query = {}
        if status:
            query["status"] = status
        logger.info(f"Counting migration tasks with query: {query}")
        count = await MigrationTask.find(query).count()
        logger.info(f"Found {count} migration tasks")
        return count

    @staticmethod
    async def update_migration_task(
        task_id: str,
        update_data: Dict[str, Any]
    ) -> Optional[MigrationTask]:
        """更新迁移任务"""
        task = await MigrationTask.get(PydanticObjectId(task_id))
        if not task:
            return None
        
        for key, value in update_data.items():
            setattr(task, key, value)
        
        task.updated_at = datetime.now(timezone.utc)
        await task.save()
        return task

    @staticmethod
    async def delete_migration_task(task_id: str) -> bool:
        """删除迁移任务"""
        task = await MigrationTask.get(PydanticObjectId(task_id))
        if not task:
            return False
        
        # 删除相关的文件状态记录
        await MigrationFileStatus.find({"task_id": str(task.id)}).delete()
        
        # 删除任务
        await task.delete()
        logger.info(f"Deleted migration task: {task_id}")
        return True

    @staticmethod
    async def get_migration_file_statuses(
        task_id: str,
        skip: int = 0,
        limit: int = 100,
        status: Optional[MigrationStatus] = None
    ) -> List[MigrationFileStatus]:
        """获取迁移文件状态列表"""
        query = {"task_id": task_id}
        if status:
            query["status"] = status
        return await MigrationFileStatus.find(query).skip(skip).limit(limit).to_list()

    @staticmethod
    async def execute_migration_task(task_id: str) -> bool:
        """执行迁移任务"""
        try:
            # 获取任务信息
            task = await MigrationTask.get(task_id)
            if not task:
                logger.error(f"找不到迁移任务: {task_id}")
                return False
            
            # 检查任务是否被中断
            if task.is_interrupted:
                logger.info(f"任务 {task_id} 已被中断，重置中断状态")
                task.is_interrupted = False
            
            # 更新任务状态为运行中
            task.status = MigrationStatus.RUNNING
            if not task.started_at:
                task.started_at = datetime.now(timezone.utc)
            task.updated_at = datetime.now(timezone.utc)
            task.last_heartbeat = datetime.now(timezone.utc)
            await task.save()
            
            # 创建源存储和目标存储适配器
            source_adapter = StorageFactory.create_adapter(task.source_storage, task.source_config)
            target_adapter = StorageFactory.create_adapter(task.target_storage, task.target_config)
            
            try:
                # 直接使用MinIO的list_objects方法
                if not isinstance(source_adapter, MinioStorageAdapter):
                    raise Exception("源存储必须是MinIO")
                    
                # 使用分页方式处理文件
                start_after = task.last_processed_file
                if start_after:
                    logger.info(f"从断点处继续执行: {start_after}")
                    task.resume_count += 1
                    task.last_resume_at = datetime.now(timezone.utc)
                    await task.save()
                
                while True:
                    # 检查任务是否被中断
                    task = await MigrationTask.get(task_id)
                    if task.is_interrupted:
                        logger.info(f"任务 {task_id} 被中断，停止执行")
                        task.status = MigrationStatus.FAILED
                        task.error_message = "任务被中断"
                        task.completed_at = datetime.now(timezone.utc)
                        await task.save()
                        return False
                    
                    # 更新心跳时间
                    task.last_heartbeat = datetime.now(timezone.utc)
                    await task.save()
                    
                    # 获取一批文件
                    objects = source_adapter.client.list_objects(
                        source_adapter.bucket_name,
                        start_after=start_after,
                        recursive=True
                    )
                    
                    # 处理这批文件
                    files = []
                    count = 0
                    last_object = None
                    
                    for obj in objects:
                        last_object = obj
                        files.append({
                            "path": obj.object_name,
                            "size": obj.size,
                            "last_modified": obj.last_modified
                        })
                        count += 1
                        
                        # 如果已经收集了足够的文件，就停止迭代
                        if count >= 1000:
                            break
                    
                    if not files:
                        break
                        
                    # 记录下一页的起始位置
                    if last_object:
                        start_after = last_object.object_name
                        # 更新任务的断点位置
                        task.last_processed_file = start_after
                        await task.save()
                        
                    # 应用文件模式过滤
                    if task.file_patterns:
                        files = [f for f in files if any(fnmatch.fnmatch(f["path"], p) for p in task.file_patterns)]
                    
                    # 更新任务统计信息
                    batch_size = sum(f["size"] for f in files)
                    task.processed_files += len(files)
                    task.processed_size += batch_size
                    await task.save()
                    
                    # 处理这批文件
                    for file in files:
                        # 再次检查任务是否被中断
                        task = await MigrationTask.get(task_id)
                        if task.is_interrupted:
                            logger.info(f"任务 {task_id} 被中断，停止执行")
                            task.status = MigrationStatus.FAILED
                            task.error_message = "任务被中断"
                            task.completed_at = datetime.now(timezone.utc)
                            await task.save()
                            return False
                        
                        file_path = file["path"]
                        file_size = file["size"]
                        
                        # 创建或获取文件状态记录
                        file_status = await MigrationFileStatus.find_one(
                            MigrationFileStatus.task_id == task_id,
                            MigrationFileStatus.file_path == file_path
                        )
                        if not file_status:
                            file_status = MigrationFileStatus(
                                task_id=task_id,
                                file_path=file_path,
                                status=MigrationStatus.PENDING,
                                source_size=file_size
                            )
                            await file_status.save()
                        
                        # 如果文件已经处理完成，跳过
                        if file_status.status == MigrationStatus.COMPLETED:
                            continue
                        
                        try:
                            # 检查目标文件是否已存在
                            if await target_adapter.file_exists(file_path):
                                target_stat = await target_adapter.get_file_stat(file_path)
                                if target_stat and target_stat["size"] == file_size:
                                    logger.info(f"文件已存在且大小相同，跳过: {file_path}")
                                    file_status.status = MigrationStatus.COMPLETED
                                    file_status.target_size = file_size
                                    file_status.completed_at = datetime.now(timezone.utc)
                                    await file_status.save()
                                    continue
                            
                            # 开始迁移文件
                            logger.info(f"开始迁移文件: {file_path}")
                            file_status.status = MigrationStatus.RUNNING
                            file_status.started_at = datetime.now(timezone.utc)
                            await file_status.save()
                            
                            # 获取源文件内容
                            file_content = await source_adapter.get_file(file_path)
                            if not file_content:
                                raise Exception("无法获取源文件内容")
                            
                            # 保存到目标存储
                            if not await target_adapter.save_file(file_path, file_content):
                                raise Exception("保存文件到目标存储失败")
                            
                            # 验证文件大小
                            target_stat = await target_adapter.get_file_stat(file_path)
                            if not target_stat or target_stat["size"] != file_size:
                                raise Exception(f"目标文件大小不匹配: 期望 {file_size}, 实际 {target_stat['size'] if target_stat else 'unknown'}")
                            
                            # 更新文件状态
                            file_status.status = MigrationStatus.COMPLETED
                            file_status.target_size = file_size
                            file_status.completed_at = datetime.now(timezone.utc)
                            await file_status.save()
                            
                        except Exception as e:
                            logger.error(f"迁移文件失败: {file_path}, 错误: {str(e)}")
                            file_status.status = MigrationStatus.FAILED
                            file_status.error_message = str(e)
                            file_status.completed_at = datetime.now(timezone.utc)
                            await file_status.save()
                            task.failed_files += 1
                            await task.save()
                    
                    # 如果没有处理完1000个文件，说明已经到达最后一页
                    if count < 1000:
                        break
                
                # 更新任务状态为完成
                task.status = MigrationStatus.COMPLETED
                task.completed_at = datetime.now(timezone.utc)
                task.last_processed_file = None  # 清除断点
                task.is_interrupted = False  # 清除中断标记
                await task.save()
                
                return True
                
            except Exception as e:
                logger.error(f"迁移任务执行失败: {str(e)}")
                task.status = MigrationStatus.FAILED
                task.error_message = str(e)
                task.completed_at = datetime.now(timezone.utc)
                task.is_interrupted = False  # 清除中断标记
                await task.save()
                return False
                
        except Exception as e:
            logger.error(f"迁移任务执行失败: {str(e)}")
            return False

    @staticmethod
    async def interrupt_migration_task(task_id: str) -> bool:
        """中断迁移任务"""
        try:
            task = await MigrationTask.get(task_id)
            if not task:
                return False
            
            # 只能中断运行中的任务
            if task.status != MigrationStatus.RUNNING:
                return False
            
            # 标记任务为中断状态
            task.is_interrupted = True
            await task.save()
            
            logger.info(f"任务 {task_id} 已标记为中断")
            return True
            
        except Exception as e:
            logger.error(f"中断任务失败: {str(e)}")
            return False

    @staticmethod
    async def check_stale_tasks() -> None:
        """检查并处理卡住的任务"""
        try:
            # 查找所有运行中但超过30分钟没有心跳的任务
            stale_time = datetime.now(timezone.utc) - timedelta(minutes=30)
            stale_tasks = await MigrationTask.find({
                "status": MigrationStatus.RUNNING,
                "$or": [
                    {"last_heartbeat": {"$lt": stale_time}},
                    {"last_heartbeat": None}
                ]
            }).to_list()
            
            for task in stale_tasks:
                logger.warning(f"发现卡住的任务: {task.id}")
                task.status = MigrationStatus.FAILED
                task.error_message = "任务执行超时"
                task.completed_at = datetime.now(timezone.utc)
                task.is_interrupted = False
                await task.save()
                
        except Exception as e:
            logger.error(f"检查卡住任务失败: {str(e)}")

    @staticmethod
    async def _list_files(
        adapter: StorageAdapter,
        patterns: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """列出存储中的文件"""
        try:
            # 使用适配器的list_files方法获取所有文件
            files = await adapter.list_files(recursive=True)
            
            # 如果指定了匹配模式，则过滤文件
            if patterns:
                files = [f for f in files if not f["is_dir"] and any(fnmatch.fnmatch(f["path"], pattern) for pattern in patterns)]
            else:
                # 只返回文件，不返回目录
                files = [f for f in files if not f["is_dir"]]
            
            return files
        except Exception as e:
            logger.error(f"Error listing files: {e}")
            return []

    @staticmethod
    async def count_migration_file_statuses(
        task_id: str,
        status: Optional[MigrationStatus] = None
    ) -> int:
        """获取迁移文件状态总数"""
        query = {"task_id": task_id}
        if status:
            query["status"] = status
        return await MigrationFileStatus.find(query).count() 