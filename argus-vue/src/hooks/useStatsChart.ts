import { useQuery } from "@tanstack/vue-query";
import { getMimeTypeStats } from '@/api/home'

interface MimeTypeStat {
  mime_type: string
  count: number
}

export const useStatsCharts = () => {
return useQuery<{ data: MimeTypeStat[] }>({
    queryKey: ['mimeTypeStats'],
    queryFn: getMimeTypeStats,
    refetchInterval: 1000 * 60 * 5 // 每5分钟刷新一次
  })
}