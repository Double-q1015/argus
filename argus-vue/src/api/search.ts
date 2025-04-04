import request from '@/utils/request'

export interface SearchResult {
  file_name: string
  description?: string
  file_path: string
  file_size: number
  file_type: string
  sha256_digest: string
  analysis_status: string
}

export interface SearchResponse {
  total: number
  results: SearchResult[]
}

export function searchSamples(query: string, limit: number = 1000) {
  return request<SearchResponse>({
    url: '/search',
    method: 'get',
    params: {
      query,
      limit
    }
  })
} 