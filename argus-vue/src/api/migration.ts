import request from '@/utils/request'
import type { MigrationTask, MigrationFileStatus, MigrationTaskCreate, MigrationTaskUpdate } from '@/types/migration'
import type { ApiListResponse } from '@/utils/request'

export const createMigrationTask = (data: MigrationTaskCreate) => {
  return request.post<MigrationTask>('/migration/tasks', data)
}

export const getMigrationTasks = (params: {
  skip?: number
  limit?: number
  status?: string
}) => {
  return request.get<ApiListResponse<MigrationTask>>('/migration/tasks', { params })
}

export const getMigrationTask = (taskId: string) => {
  return request.get<MigrationTask>(`/migration/tasks/${taskId}`).then(response => {
    console.log('getMigrationTask 响应:', response)
    return response
  })
}

export const updateMigrationTask = (taskId: string, data: MigrationTaskUpdate) => {
  return request.put<MigrationTask>(`/migration/tasks/${taskId}`, data)
}

export const deleteMigrationTask = (taskId: string) => {
  return request.delete(`/migration/tasks/${taskId}`)
}

export const executeMigrationTask = (taskId: string) => {
  return request.post(`/migration/tasks/${taskId}/execute`)
}

export const cancelMigrationTask = (taskId: string) => {
  return request.post(`/migration/tasks/${taskId}/cancel`)
}

export const getMigrationFileStatuses = (taskId: string, params: {
  skip?: number
  limit?: number
  status?: string
}) => {
  return request.get<ApiListResponse<MigrationFileStatus>>(`/migration/tasks/${taskId}/files`, { params })
}

export const getMigrationFileStatus = (taskId: string, fileId: string) => {
  return request.get<MigrationFileStatus>(`/migration/tasks/${taskId}/files/${fileId}`)
} 