import asyncio
from datetime import datetime, timedelta, timezone
import croniter
import traceback
import logging
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from app.services.task_executor import TaskExecutor
from app.services.analysis_service import AnalysisService
from app.services.analysis_config_service import AnalysisConfigService
from app.services.analysis_executor import AnalysisExecutor
from app.models.sample import Sample, SampleStatusEnum
from app.models.migration import MigrationTask, MigrationFileStatus
from app.services.migration_service import MigrationService
from app.core.config import settings
from app.core.sample_analyzer import on_sample_added
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
        self.tasks.append(asyncio.create_task(self._check_stale_tasks_loop()))
        self.tasks.append(asyncio.create_task(self._check_pending_samples()))
        
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
                logger.info("开始执行待执行的任务...")
                await TaskExecutor.execute_scheduled_tasks()
                
                # 执行待执行的分析
                logger.info("开始执行待执行的分析...")
                pending_analyses = await AnalysisService.get_pending_analyses()
                for analysis in pending_analyses:
                    await AnalysisExecutor.execute_analysis(analysis.id)
                
                # 执行待执行的分析计划
                logger.info("开始执行待执行的分析计划...")
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
                            next_run = datetime.now(timezone.utc) + timedelta(seconds=seconds)
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
                
    async def _check_stale_tasks_loop(self):
        """检查卡住任务的循环"""
        while self.is_running:
            try:
                logger.info("开始检查卡住的迁移任务...")
                
                # 初始化数据库连接
                client = AsyncIOMotorClient(settings.MONGODB_URL)
                db = client[settings.MONGODB_DB]
                
                # 初始化 Beanie
                await init_beanie(
                    database=db,
                    document_models=[
                        MigrationTask,
                        MigrationFileStatus
                    ]
                )
                
                await MigrationService.check_stale_tasks()
                logger.info("检查卡住的迁移任务完成")
                
                # 等待5分钟
                await asyncio.sleep(300)
                
            except Exception as e:
                logger.error(f"检查卡住的迁移任务时出错: {str(e)}", exc_info=True)
                await asyncio.sleep(300)  # 发生错误时等待5分钟再继续
    
    # 检查samples是pending的，添加为分析任务
    async def _check_pending_samples(self):
        while self.is_running:
            try:
                pending_samples = await Sample.find({"analysis_status": SampleStatusEnum.pending}).to_list()
                for sample in pending_samples:
                    logger.info(f"Checking sample {sample.sha256_digest}")
                    await on_sample_added(sample.sha256_digest)
            except Exception as e:
                logger.error(f"检查pending样本时出错: {str(e)}", exc_info=True)
            await asyncio.sleep(300)
                
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
task_scheduler = TaskScheduler()

def start_scheduler():
    """启动调度器"""
    try:
        # 创建并启动任务调度器
        asyncio.create_task(task_scheduler.start())
        logger.info("调度器已启动")
    except Exception as e:
        logger.error(f"启动调度器时出错: {str(e)}")

def stop_scheduler():
    """停止调度器"""
    try:
        asyncio.create_task(task_scheduler.stop())
        logger.info("调度器已停止")
    except Exception as e:
        logger.error(f"停止调度器时出错: {str(e)}") 