import request from '@/utils/request'
import axios from 'axios'

export interface DashboardStats {
  total_samples: number
  today_samples: number
  total_storage: number
  active_users: number
}

export interface RecentSample {
  sha256_digest: string
  file_name: string
  upload_time: string
  tags: string[]
}

interface DatabaseStatus {
  status: string
  message: string
}

interface MimeTypeStat {
  mime_type: string
  count: number
}

export const getDashboardStats = () => {
  return request.get<DashboardStats>('/home/stats')
}

export const getRecentSamples = (limit: number = 5) => {
  return request.get<RecentSample[]>('/home/recent-samples', {
    params: { limit }
  })
}

export const fetchDatabaseStatus = () => {
  return request.get<DatabaseStatus>('/home/database-status')
}

export const getMimeTypeStats = () => {
    return request.get<MimeTypeStat[]>('/home/mime-type-stats')
}