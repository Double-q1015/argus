import api from './config'

export interface Scale {
  id: string
  name: string
  description: string
  created_at: string
  updated_at: string
  status: 'active' | 'inactive'
  type: 'static' | 'dynamic' | 'hybrid'
  parameters: {
    [key: string]: any
  }
  results: {
    total_samples: number
    processed_samples: number
    findings: Array<{
      type: string
      severity: 'low' | 'medium' | 'high' | 'critical'
      description: string
      affected_samples: string[]
    }>
  }
}

export interface CreateScaleParams {
  name: string
  description: string
  type: Scale['type']
  parameters: Scale['parameters']
}

export interface UpdateScaleParams extends Partial<CreateScaleParams> {
  status?: Scale['status']
}

// 获取规模分析列表
export const getScales = () => {
  return api.get<{ status: string; data: { scales: Scale[] } }>('/scales')
}

// 获取规模分析详情
export const getScaleDetail = (id: string) => {
  return api.get<{ status: string; data: { scale: Scale } }>(`/scales/${id}`)
}

// 创建规模分析
export const createScale = (params: CreateScaleParams) => {
  return api.post<{ status: string; data: { scale: Scale } }>('/scales', params)
}

// 更新规模分析
export const updateScale = (id: string, params: UpdateScaleParams) => {
  return api.put<{ status: string; data: { scale: Scale } }>(`/scales/${id}`, params)
}

// 删除规模分析
export const deleteScale = (id: string) => {
  return api.delete<{ status: string }>(`/scales/${id}`)
}

// 启动规模分析
export const startScale = (id: string) => {
  return api.post<{ status: string }>(`/scales/${id}/start`)
}

// 停止规模分析
export const stopScale = (id: string) => {
  return api.post<{ status: string }>(`/scales/${id}/stop`)
}

// 获取规模分析结果
export const getScaleResults = (id: string) => {
  return api.get<{ status: string; data: { results: Scale['results'] } }>(`/scales/${id}/results`)
} 