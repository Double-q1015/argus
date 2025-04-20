import { useQuery } from '@tanstack/vue-query'
import { fetchDatabaseStatus } from '../api/home'

export const useDatabaseStatus = () => {
  return useQuery({
    queryKey: ['database-status'],
    queryFn: fetchDatabaseStatus,
    refetchInterval: 1000 * 60 * 5, // 每5分钟刷新一次
  })
}
