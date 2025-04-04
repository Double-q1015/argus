import { createRouter, createWebHistory } from 'vue-router'
import Layout from '@/layouts/Layout.vue'
import Login from '@/views/Login.vue'
import Home from '@/views/Home.vue'
import Dashboard from '@/views/Dashboard.vue'
import Settings from '@/views/Settings.vue'
import CreateYara from '@/views/yara/CreateYara.vue'
import ListYara from '@/views/yara/ListYara.vue'
import Analysis from '@/views/Analysis.vue'
import Samples from '@/views/samples/index.vue'
import ScaleList from '@/views/scales/ScaleList.vue'
import Search from '@/views/Search.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: Login,
      meta: { requiresAuth: false }
    },
    {
      path: '/',
      component: Layout,
      meta: { requiresAuth: true },
      children: [
        {
          path: '',
          name: 'Home',
          component: Home
        },
        {
          path: 'search',
          name: 'Search',
          component: Search
        },
        {
          path: 'dashboard',
          name: 'Dashboard',
          component: Dashboard
        },
        {
          path: 'analysis',
          name: 'Analysis',
          component: Analysis
        },
        {
          path: 'samples',
          name: 'Samples',
          component: Samples
        },
        {
          path: 'yara/create',
          name: 'CreateYara',
          component: CreateYara
        },
        {
          path: 'yara/list',
          name: 'ListYara',
          component: ListYara
        },
        {
          path: 'settings',
          name: 'Settings',
          component: Settings
        },
        {
          path: 'scales',
          name: 'Scales',
          component: ScaleList
        },
        {
          path: 'samples/:sha256',
          name: 'sample-detail',
          component: () => import('@/views/SampleDetail.vue')
        }
      ]
    }
  ]
})

// 路由守卫
router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('access_token')
  
  // 如果需要登录
  if (to.meta.requiresAuth) {
    if (!token) {
      // 没有token，重定向到登录页
      next({ name: 'Login' })
    } else {
      next()
    }
  } else {
    // 如果是登录页且已经有token，重定向到首页
    if (to.name === 'Login' && token) {
      next({ name: 'Home' })
    } else {
      next()
    }
  }
})

export default router 