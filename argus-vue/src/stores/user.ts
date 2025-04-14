import { defineStore } from 'pinia'

interface UserState {
  token: string | null
  username: string
  email: string
  isAuthenticated: boolean
}

export const useUserStore = defineStore('user', {
  state: (): UserState => ({
    token: localStorage.getItem('access_token'),
    username: localStorage.getItem('username') || '',
    email: localStorage.getItem('email') || '',
    isAuthenticated: !!localStorage.getItem('access_token')
  }),

  actions: {
    setToken(token: string) {
      this.token = token
      this.isAuthenticated = true
      localStorage.setItem('access_token', token)
    },

    setUserInfo(username: string, email: string) {
      this.username = username
      this.email = email
      localStorage.setItem('username', username)
      localStorage.setItem('email', email)
    },

    logout() {
      this.token = null
      this.username = ''
      this.email = ''
      this.isAuthenticated = false
      localStorage.removeItem('access_token')
      localStorage.removeItem('username')
      localStorage.removeItem('email')
    }
  }
}) 