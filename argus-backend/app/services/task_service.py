from datetime import datetime
from typing import Optional, List, Dict, Any
from beanie import PydanticObjectId
from app.models.analysis import Task, TaskCondition, TaskStatus
from app.models.user import User

class TaskService:
    @staticmethod
    async def create_task(
        name: str,
        task_type: str,
        created_by: User,
        description: Optional[str] = None,
        priority: int = 0,
        schedule: Optional[str] = None,
        conditions: Optional[List[Dict[str, Any]]] = None,
        config_id: Optional[PydanticObjectId] = None
    ) -> Task:
        """创建新任务"""
        # 创建任务
        task = Task(
            name=name,
            type=task_type,
            description=description,
            status="pending",
            priority=priority,
            created_by=created_by,
            schedule=schedule,
            config_id=config_id
        )
        await task.insert()

        # 创建任务状态
        task_status = TaskStatus(
            task_id=task,
            total_samples=0,
            processed_samples=0,
            failed_samples=[],
            current_sample=None,
            start_time=None,
            end_time=None,
            error_message=None,
            last_updated=datetime.utcnow()
        )
        await task_status.insert()

        # 创建任务条件
        if conditions:
            for i, condition in enumerate(conditions):
                task_condition = TaskCondition(
                    task_id=task,
                    condition_type=condition["type"],
                    field=condition["field"],
                    operator=condition["operator"],
                    value=condition["value"],
                    logic=condition.get("logic", "AND"),
                    order=i
                )
                await task_condition.insert()

        return task

    @staticmethod
    async def get_task(task_id: PydanticObjectId) -> Optional[Task]:
        """获取任务详情"""
        return await Task.get(task_id)

    @staticmethod
    async def get_task_status(task_id: PydanticObjectId) -> Optional[TaskStatus]:
        """获取任务状态"""
        return await TaskStatus.find_one({"task_id.$id": task_id})

    @staticmethod
    async def get_task_conditions(task_id: PydanticObjectId) -> List[TaskCondition]:
        """获取任务条件"""
        return await TaskCondition.find(
            {"task_id.$id": task_id}
        ).sort(TaskCondition.order).to_list()

    @staticmethod
    async def update_task_status(
        task_id: PydanticObjectId,
        status: str,
        current_sample: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> Optional[TaskStatus]:
        """更新任务状态"""
        task_status = await TaskStatus.find_one({"task_id.$id": task_id})
        if not task_status:
            return None

        task_status.status = status
        task_status.last_updated = datetime.utcnow()
        
        if current_sample:
            task_status.current_sample = current_sample
        if error_message:
            task_status.error_message = error_message

        await task_status.save()
        return task_status

    @staticmethod
    async def update_task_progress(
        task_id: PydanticObjectId,
        processed_samples: int,
        failed_samples: Optional[List[str]] = None,
        total_samples: Optional[int] = None
    ) -> Optional[TaskStatus]:
        """更新任务进度"""
        task_status = await TaskStatus.find_one({"task_id.$id": task_id})
        if not task_status:
            return None

        task_status.processed_samples = processed_samples
        if failed_samples is not None:
            task_status.failed_samples = failed_samples
        if total_samples is not None:
            task_status.total_samples = total_samples
        task_status.last_updated = datetime.utcnow()

        await task_status.save()
        return task_status

    @staticmethod
    async def get_pending_tasks(limit: int = 10) -> List[Task]:
        """获取待执行的任务"""
        return await Task.find(
            Task.status == "pending",
            Task.is_active == True
        ).sort(Task.priority).limit(limit).to_list()

    @staticmethod
    async def get_user_tasks(
        user_id: PydanticObjectId,
        skip: int = 0,
        limit: int = 10
    ) -> List[Task]:
        """获取用户的任务列表"""
        return await Task.find(
            Task.created_by == user_id
        ).sort(Task.created_at).skip(skip).limit(limit).to_list()

    @staticmethod
    async def deactivate_task(task_id: PydanticObjectId) -> Optional[Task]:
        """停用任务"""
        task = await Task.get(task_id)
        if not task:
            return None

        task.is_active = False
        task.updated_at = datetime.utcnow()
        await task.save()
        return task 