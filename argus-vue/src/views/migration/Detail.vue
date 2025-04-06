<template>
  <div class="migration-detail" v-loading="loading">
    <div class="header">
      <h1>迁移任务详情</h1>
      <el-button @click="$router.push('/migration')">返回</el-button>
    </div>
    
    <el-descriptions :column="2" border>
      <el-descriptions-item label="任务名称">{{ task?.name || '-' }}</el-descriptions-item>
      <el-descriptions-item label="状态">
        <el-tag :type="getStatusType(task?.status || '')">
          {{ getStatusText(task?.status || '') }}
        </el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="源存储">{{ task?.source_storage || '-' }}</el-descriptions-item>
      <el-descriptions-item label="目标存储">{{ task?.target_storage || '-' }}</el-descriptions-item>
      <el-descriptions-item label="创建时间">{{ task?.created_at || '-' }}</el-descriptions-item>
      <el-descriptions-item label="更新时间">{{ task?.updated_at || '-' }}</el-descriptions-item>
      <el-descriptions-item label="开始时间">{{ task?.started_at || '-' }}</el-descriptions-item>
      <el-descriptions-item label="完成时间">{{ task?.completed_at || '-' }}</el-descriptions-item>
      <el-descriptions-item label="描述">{{ task?.description || '-' }}</el-descriptions-item>
      <el-descriptions-item label="错误信息">{{ task?.error_message || '-' }}</el-descriptions-item>
    </el-descriptions>
    
    <div class="progress-section">
      <h2>迁移进度</h2>
      <el-progress 
        :percentage="getProgressPercentage(task)"
        :status="getProgressStatus(task?.status)"
      />
      <div class="progress-details">
        <span>已处理文件: {{ task?.processed_files || 0 }}/{{ task?.total_files || 0 }}</span>
        <span>已处理大小: {{ formatSize(task?.processed_size || 0) }}/{{ formatSize(task?.total_size || 0) }}</span>
      </div>
    </div>
    
    <div class="file-list">
      <h2>文件列表</h2>
      <el-table 
        :data="fileStatuses" 
        v-loading="loading" 
        row-key="file_path"
        height="400"
        :max-height="400"
      >
        <el-table-column prop="file_path" label="文件路径" min-width="200" show-overflow-tooltip />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">
              {{ getStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="source_size" label="源文件大小" width="120">
          <template #default="{ row }">
            {{ formatSize(row.source_size) }}
          </template>
        </el-table-column>
        <el-table-column prop="target_size" label="目标文件大小" width="120">
          <template #default="{ row }">
            {{ formatSize(row.target_size) }}
          </template>
        </el-table-column>
        <el-table-column prop="error_message" label="错误信息" min-width="200" show-overflow-tooltip />
      </el-table>
      
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50, 100]"
        :total="total"
        @current-change="loadFileStatuses"
        @size-change="handleSizeChange"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getMigrationTask, getMigrationFileStatuses } from '@/api/migration'
import { getStatusType, getStatusText, formatSize, getProgressPercentage, getProgressStatus } from '@/utils/migration'
import type { MigrationTask, MigrationFileStatus } from '@/types/migration'
import type { ApiListResponse } from '@/utils/request'

const route = useRoute()
const loading = ref(false)
const task = ref<MigrationTask>({} as MigrationTask)
const fileStatuses = ref<MigrationFileStatus[]>([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)

const loadTask = async () => {
  loading.value = true
  console.log('开始加载迁移任务')
  try {
    console.log('发送请求到 /api/v1/migration/tasks/' + route.params.id)
    const response = await getMigrationTask(route.params.id as string)
    console.log('收到响应:', response)
    console.log('响应类型:', typeof response)
    console.log('响应是否为对象:', response instanceof Object)
    console.log('响应是否为数组:', Array.isArray(response))
    console.log('响应是否有 data 属性:', 'data' in response)
    if (response && typeof response === 'object' && !Array.isArray(response)) {
      // @ts-ignore
        task.value = response
      console.log('迁移任务加载成功:', task.value)
    } else {
      console.error('迁移任务数据为空或格式不正确')
      ElMessage.error('迁移任务数据为空或格式不正确')
    }
  } catch (error) {
    console.error('加载迁移任务失败:', error)
    ElMessage.error('加载迁移任务失败')
  } finally {
    loading.value = false
  }
}

const loadFileStatuses = async () => {
  loading.value = true
  console.log('开始加载文件状态')
  try {
    const skip = (currentPage.value - 1) * pageSize.value
    const response = await getMigrationFileStatuses(route.params.id as string, {
      skip,
      limit: pageSize.value
    })
    // @ts-ignore
    fileStatuses.value = response.data
    // @ts-ignore
    total.value = response.total
    console.log('文件状态加载成功:', fileStatuses.value)
  } catch (error) {
    console.error('加载文件状态失败:', error)
    ElMessage.error('加载文件状态失败')
  } finally {
    loading.value = false
  }
}

const handleSizeChange = (newSize: number) => {
  pageSize.value = newSize
  loadFileStatuses()
}

onMounted(() => {
  loadTask()
  loadFileStatuses()
})
</script>

<style scoped>
.migration-detail {
  padding: 20px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.header h1 {
  margin: 0;
  font-size: 24px;
}

.progress-section {
  margin: 20px 0;
  padding: 20px;
  background-color: #fff;
  border-radius: 4px;
  box-shadow: 0 2px 12px 0 rgba(0,0,0,0.1);
}

.progress-section h2 {
  margin: 0 0 20px 0;
  font-size: 18px;
}

.progress-details {
  margin-top: 10px;
  display: flex;
  justify-content: space-between;
  color: #606266;
}

.file-list {
  margin-top: 20px;
  padding: 20px;
  background-color: #fff;
  border-radius: 4px;
  box-shadow: 0 2px 12px 0 rgba(0,0,0,0.1);
}

.file-list h2 {
  margin: 0 0 20px 0;
  font-size: 18px;
}

.el-pagination {
  margin-top: 20px;
  justify-content: flex-end;
}
</style>
