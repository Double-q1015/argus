<template>
  <div class="home-container">
    <el-row :gutter="20">
      <el-col :span="6" v-for="(stat, index) in stats" :key="index">
        <el-card shadow="hover" class="stat-card" :body-style="{ padding: '20px' }">
          <div class="stat-icon">
            <el-icon :size="40" :color="getIconColor(stat.key)">
              <component :is="getIcon(stat.key)" />
            </el-icon>
          </div>
          <div class="stat-content">
            <div class="stat-value">{{ formatStatValue(stat) }}</div>
            <div class="stat-label">{{ $t(`home.stats.${stat.key}`) }}</div>
          </div>
        </el-card>
      </el-col>
    </el-row>
    <!-- add upload and chart card -->
    <el-row :gutter="20" class="mt-4">
      <el-col :span="8">
        <FileUploader />
      </el-col>
      <el-col :span="16">
        <StatsChart />
      </el-col>
    </el-row>
    <el-row :gutter="20" class="mt-4">
      <el-col :span="24">
        <el-card class="recent-samples" shadow="hover">
          <template #header>
            <div class="card-header">
              <span>{{ $t('home.recentSamples.title') }}</span>
              <el-button type="text">{{ $t('home.recentSamples.viewAll') }}</el-button>
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
              :label="$t('home.recentSamples.table.sha256')"
              width="280"
            >
              <template #default="{ row }">
                <span class="monospace">{{ row.sha256_digest }}</span>
              </template>
            </el-table-column>
            <el-table-column
              prop="upload_time"
              :label="$t('home.recentSamples.table.time')"
              width="180"
            >
              <template #default="{ row }">
                {{ formatDate(row.upload_time) }}
              </template>
            </el-table-column>
            <el-table-column
              prop="file_name"
              :label="$t('home.recentSamples.table.name')"
            />
            <el-table-column
              prop="tags"
              :label="$t('home.recentSamples.table.tags')"
            >
              <template #default="{ row }">
                <el-tag
                  v-for="tag in row.tags"
                  :key="tag"
                  size="small"
                  class="tag mx-1"
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
import { ref, onMounted, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Document, Plus, FolderOpened, User } from '@element-plus/icons-vue'
import { getRecentSamples, getDashboardStats, type DashboardStats, type RecentSample } from '@/api/home'
import { formatDate } from '@/utils/format'
import FileUploader from '@/components/home/FileUpload.vue'
import StatsChart from '@/components/home/StatsChart.vue'

const { t } = useI18n()

const recentSamples = ref<RecentSample[]>([])
const loading = ref(false)
const rawStats = ref<DashboardStats>({
  total_samples: 0,
  today_samples: 0,
  total_storage: 0,
  active_users: 0
})

const stats = computed(() => [
  { key: 'totalSamples', value: rawStats.value.total_samples },
  { key: 'todaySamples', value: rawStats.value.today_samples },
  { key: 'totalStorage', value: rawStats.value.total_storage },
  { key: 'activeUsers', value: rawStats.value.active_users }
])

const formatStatValue = (stat: { key: string; value: any }) => {
  if (stat.key === 'totalStorage') {
    return formatBytes(stat.value)
  }
  return stat.value
}

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

const fetchData = async () => {
  loading.value = true
  try {
    const [samplesData, statsData] = await Promise.all([
      getRecentSamples(5),
      getDashboardStats()
    ])
    recentSamples.value = samplesData.data
    rawStats.value = statsData.data
  } catch (error) {
    ElMessage.error(t('home.message.loadError'))
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchData()
})

const getIcon = (key: string) => {
  const icons = {
    totalSamples: Document,
    todaySamples: Plus,
    totalStorage: FolderOpened,
    activeUsers: User
  }
  return icons[key as keyof typeof icons]
}

const getIconColor = (key: string) => {
  const colors = {
    totalSamples: '#409EFF',
    todaySamples: '#67C23A',
    totalStorage: '#E6A23C',
    activeUsers: '#F56C6C'
  }
  return colors[key as keyof typeof colors]
}
</script>

<style scoped>
.home-container {
  padding: 20px;
  background-color: var(--el-bg-color);
  min-height: 100vh;
}

.stat-card {
  transition: all 0.3s;
  border-radius: 8px;
  overflow: hidden;
}

.stat-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.stat-icon {
  display: flex;
  justify-content: center;
  margin-bottom: 16px;
}

.stat-content {
  text-align: center;
}

.stat-value {
  font-size: 28px;
  font-weight: bold;
  color: var(--el-text-color-primary);
  margin-bottom: 8px;
  line-height: 1.2;
}

.stat-label {
  font-size: 14px;
  color: var(--el-text-color-secondary);
  line-height: 1.4;
}

.mt-4 {
  margin-top: 20px;
}

.mx-1 {
  margin: 0 4px;
}

.monospace {
  font-family: monospace;
}

.recent-samples {
  margin-top: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.tag {
  margin-right: 5px;
  margin-bottom: 5px;
}
</style> 