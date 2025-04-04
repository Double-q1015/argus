import asyncio
from datetime import datetime, timedelta
import croniter
import traceback
import logging
from app.services.task_executor import TaskExecutor
from app.services.analysis_service import AnalysisService
from app.services.analysis_config_service import AnalysisConfigService
from app.services.analysis_executor import AnalysisExecutor
from app.models.sample import Sample

# 配置日志
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class TaskScheduler:
    """任务调度器"""
    
    def __init__(self):
        self.is_running = False
        self.tasks = []
        
    async def start(self):
        """启动调度器"""
        if self.is_running:
            return
            
        self.is_running = True
        self.tasks.append(asyncio.create_task(self._schedule_loop()))
        
    async def stop(self):
        """停止调度器"""
        self.is_running = False
        for task in self.tasks:
            task.cancel()
        self.tasks.clear()
        
    async def _schedule_loop(self):
        """调度循环"""
        while self.is_running:
            try:
                # 执行待执行的任务
                await TaskExecutor.execute_scheduled_tasks()
                
                # 执行待执行的分析
                pending_analyses = await AnalysisService.get_pending_analyses()
                for analysis in pending_analyses:
                    await AnalysisExecutor.execute_analysis(analysis.id)
                
                # 执行待执行的分析计划
                pending_schedules = await AnalysisConfigService.get_pending_schedules()
                for schedule in pending_schedules:
                    config = await AnalysisConfigService.get_config(schedule.config_id)
                    if config:
                        # 获取配置关联的样本
                        samples = await Sample.find().to_list()
                        sample_ids = [sample.id for sample in samples]
                        
                        # 执行分析
                        await AnalysisExecutor.execute_batch_analysis(
                            sample_ids=sample_ids,
                            analysis_types=[config.analysis_type],
                            auto_analyze=config.auto_analyze
                        )
                        
                        # 更新计划执行时间
                        if schedule.schedule_type == "cron":
                            next_run = TaskScheduler.parse_cron(schedule.schedule_value)
                        elif schedule.schedule_type == "interval":
                            seconds = TaskScheduler.parse_interval(schedule.schedule_value)
                            next_run = datetime.utcnow() + timedelta(seconds=seconds)
                        else:
                            next_run = None
                            
                        if next_run:
                            await AnalysisConfigService.update_schedule_run_time(
                                schedule.id,
                                next_run
                            )
                
                # 等待一段时间
                await asyncio.sleep(60)  # 每分钟检查一次
                
            except Exception as e:
                error_msg = f"Error in schedule loop: {str(e)}\n{traceback.format_exc()}"
                logger.error(error_msg)
                await asyncio.sleep(60)  # 发生错误时等待一分钟再继续
                
    @staticmethod
    def parse_cron(cron_expression: str) -> datetime:
        """解析cron表达式，返回下次执行时间"""
        try:
            cron = croniter.croniter(cron_expression, datetime.utcnow())
            return cron.get_next(datetime)
        except Exception as e:
            logger.error(f"Error parsing cron expression: {e}")
            return None
            
    @staticmethod
    def parse_interval(interval: str) -> int:
        """解析时间间隔，返回秒数"""
        try:
            # 格式: 1h, 30m, 45s
            value = int(interval[:-1])
            unit = interval[-1].lower()
            
            if unit == 'h':
                return value * 3600
            elif unit == 'm':
                return value * 60
            elif unit == 's':
                return value
            else:
                raise ValueError(f"Invalid interval unit: {unit}")
                
        except Exception as e:
            logger.error(f"Error parsing interval: {e}")
            return None

# 创建全局调度器实例
scheduler = TaskScheduler() 