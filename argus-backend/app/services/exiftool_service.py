import asyncio
from typing import List, Optional
from datetime import datetime
from app.models.exiftool_task import ExifToolTask
from app.models.sample import Sample
from app.core.exiftool_analyzer import perform_exiftool_analysis
from app.core.storage import create_minio_client
from app.core.config import settings

class ExifToolService:
    def __init__(self):
        self.minio_client = create_minio_client()

    async def create_task(self, name: str, description: Optional[str] = None) -> ExifToolTask:
        """创建新的ExifTool分析任务"""
        task = ExifToolTask(
            name=name,
            description=description
        )
        await task.insert()
        return task

    async def get_task(self, task_id: str) -> Optional[ExifToolTask]:
        """获取任务信息"""
        return await ExifToolTask.get(task_id)

    async def list_tasks(self, skip: int = 0, limit: int = 100) -> List[ExifToolTask]:
        """获取任务列表"""
        return await ExifToolTask.find().skip(skip).limit(limit).to_list()

    async def start_task(self, task_id: str) -> bool:
        """启动分析任务"""
        task = await self.get_task(task_id)
        if not task:
            return False

        if task.status == "running":
            return False

        # 获取所有样本
        samples = await Sample.find().to_list()
        task.task_status.total_samples = len(samples)
        await task.save()

        # 启动异步任务
        asyncio.create_task(self._process_samples(task, samples))
        return True

    async def _process_samples(self, task: ExifToolTask, samples: List[Sample]):
        """处理样本列表"""
        try:
            await task.start()
            failed_samples = []

            for i, sample in enumerate(samples):
                try:
                    # 更新当前处理的样本
                    await task.update_progress(
                        processed=i,
                        current=sample.sha256_digest
                    )

                    # 执行ExifTool分析
                    metadata = await perform_exiftool_analysis(
                        file_path="",  # 空文件路径，使用MinIO
                        minio_client=self.minio_client,
                        bucket_name=settings.MINIO_BUCKET_NAME,
                        object_name=sample.sha256_digest
                    )

                    # 保存分析结果
                    task.results[sample.sha256_digest] = metadata.to_dict()
                    await task.save()

                except Exception as e:
                    failed_samples.append(sample.sha256_digest)
                    print(f"处理样本 {sample.sha256_digest} 时出错: {str(e)}")

            # 更新最终进度
            await task.update_progress(
                processed=len(samples),
                failed=failed_samples
            )

            # 完成任务
            await task.complete()

        except Exception as e:
            await task.fail(str(e))
            print(f"任务执行失败: {str(e)}")

    async def stop_task(self, task_id: str) -> bool:
        """停止分析任务"""
        task = await self.get_task(task_id)
        if not task or task.status != "running":
            return False

        # 这里可以添加停止逻辑，比如设置一个标志位
        task.status = "stopped"
        await task.save()
        return True 