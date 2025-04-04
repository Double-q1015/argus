import { http } from './http'

export interface LoginData {
  username: string
  password: string
  captcha: string
  client_id: string
}

export interface RegisterData {
  username: string
  email: string
  password: string
}

export interface TokenResponse {
  access_token: string
  token_type: string
}

export const login = async (data: LoginData): Promise<TokenResponse> => {
  return http.post('/auth/login', data)
}

export const register = async (data: RegisterData) => {
  return http.post('/auth/register', data)
}

export default {
  login,
  register
} 