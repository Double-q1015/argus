from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from beanie import PydanticObjectId
from app.models.analysis import AnalysisConfig, AnalysisSchedule
from app.models.user import User

class AnalysisConfigService:
    @staticmethod
    async def create_config(
        name: str,
        analysis_type: str,
        created_by: User,
        description: Optional[str] = None,
        auto_analyze: bool = False,
        priority: int = 0,
        resource_limits: Optional[Dict[str, int]] = None
    ) -> AnalysisConfig:
        """创建分析配置"""
        # 确保created_by是User对象
        if not isinstance(created_by, User):
            raise ValueError("created_by must be a User object")

        config = AnalysisConfig(
            name=name,
            analysis_type=analysis_type,
            description=description,
            auto_analyze=auto_analyze,
            priority=priority,
            resource_limits=resource_limits or {},
            created_by=created_by
        )
        await config.insert()
        return config

    @staticmethod
    async def get_config(config_id: PydanticObjectId) -> Optional[AnalysisConfig]:
        """获取分析配置"""
        return await AnalysisConfig.get(config_id)

    @staticmethod
    async def get_configs(
        analysis_type: Optional[str] = None,
        is_active: Optional[bool] = True,
        skip: int = 0,
        limit: int = 10
    ) -> List[AnalysisConfig]:
        """获取分析配置列表"""
        query = AnalysisConfig.find()
        if analysis_type:
            query = query.find(AnalysisConfig.analysis_type == analysis_type)
        if is_active is not None:
            query = query.find(AnalysisConfig.is_active == is_active)
        return await query.sort(AnalysisConfig.created_at).skip(skip).limit(limit).to_list()

    @staticmethod
    async def update_config(
        config_id: PydanticObjectId,
        name: Optional[str] = None,
        description: Optional[str] = None,
        auto_analyze: Optional[bool] = None,
        priority: Optional[int] = None,
        resource_limits: Optional[Dict[str, int]] = None,
        is_active: Optional[bool] = None
    ) -> Optional[AnalysisConfig]:
        """更新分析配置"""
        config = await AnalysisConfig.get(config_id)
        if not config:
            return None

        if name is not None:
            config.name = name
        if description is not None:
            config.description = description
        if auto_analyze is not None:
            config.auto_analyze = auto_analyze
        if priority is not None:
            config.priority = priority
        if resource_limits is not None:
            config.resource_limits = resource_limits
        if is_active is not None:
            config.is_active = is_active

        config.updated_at = datetime.utcnow()
        await config.save()
        return config

    @staticmethod
    async def create_schedule(
        config_id: PydanticObjectId,
        schedule_type: str,
        schedule_value: str
    ) -> AnalysisSchedule:
        """创建分析计划"""
        schedule = AnalysisSchedule(
            config_id=config_id,
            schedule_type=schedule_type,
            schedule_value=schedule_value
        )
        await schedule.insert()
        return schedule

    @staticmethod
    async def get_schedule(schedule_id: PydanticObjectId) -> Optional[AnalysisSchedule]:
        """获取分析计划"""
        return await AnalysisSchedule.get(schedule_id)

    @staticmethod
    async def get_config_schedules(
        config_id: PydanticObjectId,
        is_active: Optional[bool] = True
    ) -> List[AnalysisSchedule]:
        """获取配置的分析计划"""
        query = AnalysisSchedule.find(AnalysisSchedule.config_id == config_id)
        if is_active is not None:
            query = query.find(AnalysisSchedule.is_active == is_active)
        return await query.to_list()

    @staticmethod
    async def update_schedule(
        schedule_id: PydanticObjectId,
        schedule_type: Optional[str] = None,
        schedule_value: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> Optional[AnalysisSchedule]:
        """更新分析计划"""
        schedule = await AnalysisSchedule.get(schedule_id)
        if not schedule:
            return None

        if schedule_type is not None:
            schedule.schedule_type = schedule_type
        if schedule_value is not None:
            schedule.schedule_value = schedule_value
        if is_active is not None:
            schedule.is_active = is_active

        await schedule.save()
        return schedule

    @staticmethod
    async def get_pending_schedules(limit: int = 10) -> List[AnalysisSchedule]:
        """获取待执行的分析计划"""
        return await AnalysisSchedule.find(
            AnalysisSchedule.is_active == True,
            AnalysisSchedule.next_run <= datetime.utcnow()
        ).limit(limit).to_list()

    @staticmethod
    async def update_schedule_run_time(
        schedule_id: PydanticObjectId,
        next_run: datetime
    ) -> Optional[AnalysisSchedule]:
        """更新计划执行时间"""
        schedule = await AnalysisSchedule.get(schedule_id)
        if not schedule:
            return None

        schedule.last_run = datetime.utcnow()
        schedule.next_run = next_run
        await schedule.save()
        return schedule 