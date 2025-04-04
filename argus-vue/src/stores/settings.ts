import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

export const useSettingsStore = defineStore('settings', () => {
  // 从 localStorage 加载初始值
  const theme = ref(localStorage.getItem('theme') || 'light')
  const language = ref(localStorage.getItem('language') || 'zh-CN')
  const notifications = ref(localStorage.getItem('notifications') === 'true')

  // 监听变化并保存到 localStorage
  watch(theme, (newValue) => {
    localStorage.setItem('theme', newValue)
    applyTheme(newValue)
  })

  watch(language, (newValue) => {
    localStorage.setItem('language', newValue)
    document.documentElement.lang = newValue
  })

  watch(notifications, (newValue) => {
    localStorage.setItem('notifications', String(newValue))
  })

  // 应用主题
  const applyTheme = (themeName: string) => {
    // 移除所有主题相关的类
    document.documentElement.classList.remove('light', 'dark')
    
    if (themeName === 'auto') {
      // 根据系统主题设置
      if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.documentElement.classList.add('dark')
      } else {
        document.documentElement.classList.add('light')
      }
    } else {
      // 直接应用指定的主题
      document.documentElement.classList.add(themeName)
    }
  }

  // 初始化主题
  applyTheme(theme.value)

  return {
    theme,
    language,
    notifications,
    applyTheme
  }
}) 