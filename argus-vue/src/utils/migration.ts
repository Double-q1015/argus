import type { MigrationTask } from '@/types/migration'

export const getStatusType = (status: string) => {
  const map: Record<string, string> = {
    pending: 'info',
    running: 'primary',
    completed: 'success',
    failed: 'danger',
    cancelled: 'warning'
  };
  return map[status] || 'info';
};

export const getStatusText = (status: string) => {
  const map: Record<string, string> = {
    pending: '等待执行',
    running: '执行中',
    completed: '已完成',
    failed: '失败',
    cancelled: '已取消'
  };
  return map[status] || status;
};

export const formatSize = (bytes: number) => {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
};

export const getProgressPercentage = (task: MigrationTask | undefined) => {
  if (!task || !task.total_files) return 0;
  return Math.round((task.processed_files / task.total_files) * 100);
};

export const getProgressStatus = (status: string | undefined) => {
  if (!status) return '';
  if (status === 'failed') return 'exception';
  if (status === 'completed') return 'success';
  return '';
}; 