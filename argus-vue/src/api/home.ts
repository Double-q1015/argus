import request from '@/utils/request'

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

export const getDashboardStats = () => {
  return request.get<DashboardStats>('/home/stats')
}

export const getRecentSamples = (limit: number = 5) => {
  return request.get<RecentSample[]>('/home/recent-samples', {
    params: { limit }
  })
} 