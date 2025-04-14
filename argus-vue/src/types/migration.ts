export enum MigrationStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled'
}

export interface MigrationTask {
  id: string
  name: string
  description?: string
  source_storage: string
  source_config: Record<string, any>
  target_storage: string
  target_config: Record<string, any>
  file_patterns?: string[]
  status: MigrationStatus
  created_at: string
  updated_at: string
  started_at?: string
  completed_at?: string
  error_message?: string
  total_files: number
  processed_files: number
  failed_files: number
  total_size: number
  processed_size: number
}

export interface MigrationFileStatus {
  id: string
  task_id: string
  file_path: string
  status: MigrationStatus
  source_size?: number
  target_size?: number
  started_at?: string
  completed_at?: string
  error_message?: string
}

export interface MinioStorageConfig {
  endpoint: string
  access_key: string
  secret_key: string
  bucket_name: string
  prefix?: string
  secure?: boolean
}

export interface LocalStorageConfig {
  base_path: string
  directory_depth?: number
}

export type StorageConfig = MinioStorageConfig | LocalStorageConfig

export interface MigrationTaskCreate {
  name: string
  description?: string
  source_storage: 'minio' | 'local'
  source_config: StorageConfig
  target_storage: 'minio' | 'local'
  target_config: StorageConfig
  file_patterns?: string[]
}

export interface MigrationTaskUpdate {
  name?: string
  description?: string
  file_patterns?: string[]
} 