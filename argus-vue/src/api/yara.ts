import { http } from './http'

export interface YaraRule {
  id: string
  name: string
  description: string
  content: string
  status: string
  created_at: string
  updated_at: string
  created_by: string
}

export interface CreateYaraRule {
  name: string
  description: string
  content: string
}

export interface UpdateYaraRule {
  name?: string
  description?: string
  content?: string
  status?: string
}

export interface GetRulesParams {
  skip?: number
  limit?: number
}

export const yaraApi = {
  // 创建规则
  createRule(rule: CreateYaraRule) {
    return http.post<YaraRule>('/yara/rules', rule)
  },

  // 获取规则列表
  getRules: (params: GetRulesParams) => {
    return http.get<YaraRule[]>('/yara/rules', { params })
  },

  // 获取单个规则
  getRule(id: string) {
    return http.get<YaraRule>(`/yara/rules/${id}`)
  },

  // 更新规则
  updateRule(id: string, rule: UpdateYaraRule) {
    return http.put<YaraRule>(`/yara/rules/${id}`, rule)
  },

  // 删除规则
  deleteRule(id: string) {
    return http.delete(`/yara/rules/${id}`)
  }
} 