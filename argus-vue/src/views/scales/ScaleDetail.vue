<template>
  <div class="scale-detail">
    <el-card v-loading="store.detailLoading">
      <template #header>
        <div class="card-header">
          <span>规模分析详情</span>
          <div class="header-actions">
            <el-button
              v-if="scale?.status === 'inactive'"
              type="success"
              @click="handleStart"
            >
              启动分析
            </el-button>
            <el-button
              v-else
              type="warning"
              @click="handleStop"
            >
              停止分析
            </el-button>
            <el-button type="primary" @click="handleEdit">编辑</el-button>
            <el-popconfirm
              title="确定要删除这个规模分析吗？"
              @confirm="handleDelete"
            >
              <template #reference>
                <el-button type="danger">删除</el-button>
              </template>
            </el-popconfirm>
          </div>
        </div>
      </template>

      <el-descriptions :column="2" border>
        <el-descriptions-item label="名称">
          {{ scale?.name }}
        </el-descriptions-item>
        <el-descriptions-item label="类型">
          <el-tag :type="getTypeTagType(scale?.type)">
            {{ formatType(scale?.type) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="getStatusTagType(scale?.status)">
            {{ formatStatus(scale?.status) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="创建时间">
          {{ formatDate(scale?.created_at) }}
        </el-descriptions-item>
        <el-descriptions-item label="更新时间">
          {{ formatDate(scale?.updated_at) }}
        </el-descriptions-item>
        <el-descriptions-item label="描述" :span="2">
          {{ scale?.description }}
        </el-descriptions-item>
        <el-descriptions-item label="参数" :span="2">
          <pre>{{ JSON.stringify(scale?.parameters, null, 2) }}</pre>
        </el-descriptions-item>
      </el-descriptions>

      <div v-if="scale?.results" class="results-section">
        <h3>分析结果</h3>
        
        <el-progress
          :percentage="progressPercentage"
          :status="progressStatus"
          :format="progressFormat"
          class="progress-bar"
        />

        <el-collapse v-model="activeCollapse">
          <el-collapse-item title="发现问题" name="findings">
            <el-table :data="scale.results.findings">
              <el-table-column prop="type" label="类型" width="150" />
              <el-table-column prop="severity" label="严重程度" width="120">
                <template #default="{ row }">
                  <el-tag :type="getSeverityTagType(row.severity)">
                    {{ formatSeverity(row.severity) }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="description" label="描述" min-width="300" show-overflow-tooltip />
              <el-table-column label="受影响样本" width="120">
                <template #default="{ row }">
                  <el-popover
                    placement="right"
                    trigger="hover"
                    :width="400"
                  >
                    <template #reference>
                      <el-button link>
                        {{ row.affected_samples.length }} 个样本
                      </el-button>
                    </template>
                    <div class="affected-samples">
                      <div
                        v-for="sample in row.affected_samples"
                        :key="sample"
                        class="affected-sample"
                      >
                        <router-link :to="`/samples/${sample}`">
                          {{ sample }}
                        </router-link>
                      </div>
                    </div>
                  </el-popover>
                </template>
              </el-table-column>
            </el-table>
          </el-collapse-item>
        </el-collapse>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScalesStore } from '@/stores/scales'
import type { Scale } from '@/api/scales'

const route = useRoute()
const router = useRouter()
const store = useScalesStore()
const activeCollapse = ref(['findings'])

const scale = computed(() => store.currentScale)

// 进度相关
const progressPercentage = computed(() => {
  if (!scale.value?.results) return 0
  const { total_samples, processed_samples } = scale.value.results
  return Math.round((processed_samples / total_samples) * 100)
})

const progressStatus = computed(() => {
  if (!scale.value) return ''
  return scale.value.status === 'active' ? 'success' : ''
})

const progressFormat = (percentage: number) => {
  if (!scale.value?.results) return '0/0'
  const { total_samples, processed_samples } = scale.value.results
  return `${processed_samples}/${total_samples}`
}

// 格式化函数
const formatDate = (timestamp?: string) => {
  if (!timestamp) return ''
  return new Date(timestamp).toLocaleString()
}

const formatType = (type?: Scale['type']) => {
  if (!type) return ''
  const typeMap = {
    static: '静态分析',
    dynamic: '动态分析',
    hybrid: '混合分析'
  }
  return typeMap[type] || type
}

const formatStatus = (status?: Scale['status']) => {
  if (!status) return ''
  const statusMap = {
    active: '运行中',
    inactive: '已停止'
  }
  return statusMap[status] || status
}

const formatSeverity = (severity: string) => {
  const severityMap = {
    low: '低',
    medium: '中',
    high: '高',
    critical: '严重'
  }
  return severityMap[severity as keyof typeof severityMap] || severity
}

const getTypeTagType = (type?: Scale['type']) => {
  if (!type) return ''
  const typeMap = {
    static: '',
    dynamic: 'success',
    hybrid: 'warning'
  }
  return typeMap[type] || ''
}

const getStatusTagType = (status?: Scale['status']) => {
  if (!status) return ''
  const statusMap = {
    active: 'success',
    inactive: 'info'
  }
  return statusMap[status] || ''
}

const getSeverityTagType = (severity: string) => {
  const severityMap = {
    low: 'info',
    medium: 'warning',
    high: 'danger',
    critical: 'danger'
  }
  return severityMap[severity as keyof typeof severityMap] || ''
}

// 事件处理函数
const handleEdit = () => {
  router.push(`/scales/${route.params.id}/edit`)
}

const handleStart = async () => {
  if (scale.value) {
    await store.startScale(scale.value.id)
  }
}

const handleStop = async () => {
  if (scale.value) {
    await store.stopScale(scale.value.id)
  }
}

const handleDelete = async () => {
  if (scale.value) {
    const success = await store.deleteScale(scale.value.id)
    if (success) {
      router.push('/scales')
    }
  }
}

// 定时更新结果
let timer: number | null = null

const updateResults = async () => {
  if (scale.value?.status === 'active') {
    await store.fetchScaleResults(route.params.id as string)
  }
}

onMounted(async () => {
  await store.fetchScaleDetail(route.params.id as string)
  timer = window.setInterval(updateResults, 5000)
})

onBeforeUnmount(() => {
  if (timer) {
    clearInterval(timer)
  }
  store.clearCurrentScale()
})
</script>

<style scoped>
.scale-detail {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-actions {
  display: flex;
  gap: 10px;
}

.results-section {
  margin-top: 20px;
}

.results-section h3 {
  margin-bottom: 20px;
}

.progress-bar {
  margin: 20px 0;
}

pre {
  background-color: #f5f7fa;
  padding: 16px;
  border-radius: 4px;
  overflow-x: auto;
  margin: 0;
}

.affected-samples {
  max-height: 300px;
  overflow-y: auto;
}

.affected-sample {
  padding: 4px 0;
}

:deep(.el-descriptions) {
  margin-bottom: 20px;
}

:deep(.el-collapse-item__content) {
  padding: 20px;
}
</style> 