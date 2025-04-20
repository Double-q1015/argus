import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import './styles/theme.css'
import App from './App.vue'
import router from './router'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import i18n from './i18n'

const app = createApp(App)
const pinia = createPinia()
// 创建 QueryClient 实例
const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: 3,
        refetchOnWindowFocus: false,
        staleTime: 5 * 60 * 1000,
      },
    },
  })
  
  // 使用 Vue Query 插件
app.use(VueQueryPlugin, { queryClient })
app.use(ElementPlus)
app.use(router)
app.use(pinia)
app.use(i18n)
app.mount('#app')
