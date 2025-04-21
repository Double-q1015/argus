import { createRouter, createWebHistory } from 'vue-router'
import Layout from '@/layouts/Layout.vue'
import Login from '@/views/Login.vue'
import Home from '@/views/Home.vue'
import Settings from '@/views/Settings.vue'
import CreateYara from '@/views/yara/CreateYara.vue'
import ListYara from '@/views/yara/ListYara.vue'
import Analysis from '@/views/Analysis.vue'
import Samples from '@/views/samples/index.vue'
import Search from '@/views/Search.vue'
import TaskList from '@/views/TaskList.vue'
import TaskDetail from '@/views/TaskDetail.vue'
import TaskCreate from '@/views/TaskCreate.vue'

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
          path: 'samples/:sha256',
          name: 'malware-detail',
          component: () => import('@/views/samples/MalwareDetail.vue')
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
          path: 'tasks',
          name: 'TaskList',
          component: TaskList
        },
        {
          path: 'tasks/create',
          name: 'TaskCreate',
          component: TaskCreate
        },
        {
          path: 'tasks/:id',
          name: 'TaskDetail',
          component: TaskDetail
        },
        {
          path: 'migration',
          name: 'Migration',
          component: () => import('@/views/migration/List.vue')
        },
        {
          path: 'migration/create',
          name: 'MigrationCreate',
          component: () => import('@/views/migration/Create.vue')
        },
        {
          path: 'migration/:id',
          name: 'MigrationDetail',
          component: () => import('@/views/migration/Detail.vue')
        }
      ]
    },
    {
      path: '/demo/pe-overview',
      name: 'PeOverviewDemo',
      component: () => import('@/components/FileOverviews/PeOverview/demo.vue'),
      meta: {
        title: 'PE Overview Demo'
      }
    }
  ]
})

// 路由守卫
router.beforeEach((to, _from, next) => {
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