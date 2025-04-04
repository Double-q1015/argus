import { http } from './http'

export interface AnalysisResult {
  filename: string
  file_id: string
  status: 'success' | 'error'
  result?: any
  error?: string
}

export interface AnalysisResponse {
  message: string
  results: AnalysisResult[]
}

export const analysisApi = {
  // 上传并分析文件
  analyzeFiles(files: File[]) {
    const formData = new FormData()
    files.forEach(file => {
      formData.append('files', file)
    })
    
    return http.post<AnalysisResponse>('/api/v1/analysis/files', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    })
  }
} 