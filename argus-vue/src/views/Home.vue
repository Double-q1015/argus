<template>
  <div class="home-container">
    <el-row :gutter="20">
      <el-col :span="6">
        <el-card class="stat-card">
          <template #header>
            <div class="card-header">
              <span>总样本数</span>
              <el-button class="button" text>
                <el-icon><Document /></el-icon>
              </el-button>
            </div>
          </template>
          <div class="stat-value">{{ stats.total_samples }}</div>
        </el-card>
      </el-col>
      
      <el-col :span="6">
        <el-card class="stat-card">
          <template #header>
            <div class="card-header">
              <span>今日新增</span>
              <el-button class="button" text>
                <el-icon><Plus /></el-icon>
              </el-button>
            </div>
          </template>
          <div class="stat-value">{{ stats.today_samples }}</div>
        </el-card>
      </el-col>
      
      <el-col :span="6">
        <el-card class="stat-card">
          <template #header>
            <div class="card-header">
              <span>总存储量</span>
              <el-button class="button" text>
                <el-icon><FolderOpened /></el-icon>
              </el-button>
            </div>
          </template>
          <div class="stat-value">{{ formatBytes(stats.total_storage) }}</div>
        </el-card>
      </el-col>
      
      <el-col :span="6">
        <el-card class="stat-card">
          <template #header>
            <div class="card-header">
              <span>活跃用户</span>
              <el-button class="button" text>
                <el-icon><User /></el-icon>
              </el-button>
            </div>
          </template>
          <div class="stat-value">{{ stats.active_users }}</div>
        </el-card>
      </el-col>
    </el-row>
    
    <el-row :gutter="20" class="mt-4">
      <el-col :span="24">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>最近添加的样本</span>
              <el-button class="button" text>查看全部</el-button>
            </div>
          </template>
          <el-table
            v-loading="loading"
            :data="recentSamples"
            style="width: 100%"
            size="small"
          >
            <el-table-column
              prop="sha256_digest"
              label="SHA256摘要"
              width="280"
            >
              <template #default="{ row }">
                <span class="monospace">{{ row.sha256_digest }}</span>
              </template>
            </el-table-column>
            <el-table-column
              prop="upload_time"
              label="时间"
              width="180"
            >
              <template #default="{ row }">
                {{ formatDate(row.upload_time) }}
              </template>
            </el-table-column>
            <el-table-column
              prop="file_name"
              label="名称"
            />
            <el-table-column
              prop="tags"
              label="标签"
            >
              <template #default="{ row }">
                <el-tag
                  v-for="tag in row.tags"
                  :key="tag"
                  size="small"
                  class="mx-1"
                  style="margin-right: 4px"
                >
                  {{ tag }}
                </el-tag>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { getRecentSamples, getDashboardStats, type DashboardStats } from '@/api/home'
import type { SampleResponse } from '@/api/samples'
import { formatDate, formatBytes } from '@/utils/format'
import { Document, Plus, FolderOpened, User } from '@element-plus/icons-vue'

const recentSamples = ref<SampleResponse[]>([])
const loading = ref(false)
const stats = ref<DashboardStats>({
  total_samples: 0,
  today_samples: 0,
  total_storage: 0,
  active_users: 0
})

const fetchData = async () => {
  loading.value = true
  try {
    const [samplesData, statsData] = await Promise.all([
      getRecentSamples(5),
      getDashboardStats()
    ])
    recentSamples.value = samplesData
    stats.value = statsData
  } catch (error) {
    console.error('获取数据失败:', error)
    ElMessage.error('获取数据失败')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchData()
})
</script>

<style scoped>
.home-container {
  padding: 20px;
  background-color: var(--el-bg-color);
  min-height: 100vh;
}

.stat-card {
  .stat-value {
    font-size: 24px;
    font-weight: bold;
    color: var(--el-color-primary);
    text-align: center;
    margin-top: 10px;
  }
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.mt-4 {
  margin-top: 20px;
}

.mx-1 {
  margin: 0 4px;
}

.announcement {
  margin-bottom: 15px;
  
  h4 {
    margin: 0 0 10px 0;
    color: var(--el-text-color-primary);
  }
  
  p {
    margin: 0;
    color: var(--el-text-color-regular);
  }
  
  .announcement-time {
    margin-top: 5px;
    font-size: 12px;
    color: var(--el-text-color-secondary);
  }
}

.el-divider {
  margin: 15px 0;
  background-color: var(--el-border-color);
}

.monospace {
  font-family: monospace;
}

h2 {
  margin-bottom: 20px;
}
</style> 