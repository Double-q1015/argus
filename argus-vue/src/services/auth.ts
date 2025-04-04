import api from '@/utils/api'

export interface LoginForm {
  username: string
  password: string
}

export interface LoginResponse {
  access_token: string
  token_type: string
  expires_in: number
}

export const login = async (data: LoginForm): Promise<LoginResponse> => {
  return api.post('/auth/login', data)
}

export const logout = async (): Promise<void> => {
  localStorage.removeItem('access_token')
  window.location.href = '/login'
} 