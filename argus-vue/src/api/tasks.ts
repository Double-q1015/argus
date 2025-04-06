import { http } from './http'

export interface Task {
  id: string
  name: string
  description?: string
  type: string
  status: 'created' | 'pending' | 'running' | 'completed' | 'failed'
  priority: number
  created_by: string
  created_at: string
  updated_at: string
  schedule?: string
  is_active: boolean
  config_id?: string
}

export interface TaskCreate {
  name: string
  description?: string
  type: string
  priority?: number
  schedule?: string
  config_id?: string
}

export interface TaskStatus {
  task_id: string
  status: string
  start_time?: string
  end_time?: string
  current_sample?: string
  processed_samples: number
  failed_samples: string[]
  total_samples: number
  error_message?: string
  created_at: string
  updated_at: string
}

export const tasksApi = {
  // 获取任务列表
  getTasks(params?: { skip?: number; limit?: number; status?: string }): Promise<Task[]> {
    return http.get('/tasks/', { params })
  },

  // 获取任务详情
  getTask(taskId: string): Promise<Task> {
    return http.get(`/tasks/${taskId}`)
  },

  // 创建任务
  createTask(task: TaskCreate): Promise<Task> {
    return http.post('/tasks/', task)
  },

  // 删除任务
  deleteTask(taskId: string): Promise<void> {
    return http.delete(`/tasks/${taskId}`)
  },

  // 启动任务
  startTask(taskId: string): Promise<void> {
    return http.post(`/tasks/${taskId}/start`)
  },

  // 停用任务
  deactivateTask(taskId: string): Promise<void> {
    return http.post(`/tasks/${taskId}/deactivate`)
  }
} 