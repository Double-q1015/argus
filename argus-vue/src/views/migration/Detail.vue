<template>
  <div class="migration-detail" v-loading="loading">
    <div class="header">
      <h1>{{ $t('migration.detail.title') }}</h1>
      <el-button @click="$router.push('/migration')">{{ $t('migration.detail.back') }}</el-button>
    </div>
    
    <el-descriptions :column="2" border>
      <el-descriptions-item :label="$t('migration.detail.labels.name')">{{ task?.name || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="$t('migration.detail.labels.status')">
        <el-tag :type="getStatusType(task?.status || '')">
          {{ getStatusText(task?.status || '') }}
        </el-tag>
      </el-descriptions-item>
      <el-descriptions-item :label="$t('migration.detail.labels.sourceStorage')">{{ task?.source_storage || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="$t('migration.detail.labels.targetStorage')">{{ task?.target_storage || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="$t('migration.detail.labels.createdAt')">{{ task?.created_at || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="$t('migration.detail.labels.updatedAt')">{{ task?.updated_at || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="$t('migration.detail.labels.startedAt')">{{ task?.started_at || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="$t('migration.detail.labels.completedAt')">{{ task?.completed_at || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="$t('migration.detail.labels.description')">{{ task?.description || '-' }}</el-descriptions-item>
      <el-descriptions-item :label="$t('migration.detail.labels.errorMessage')">{{ task?.error_message || '-' }}</el-descriptions-item>
    </el-descriptions>
    
    <div class="progress-section">
      <h2>{{ $t('migration.detail.progress.title') }}</h2>
      <el-progress 
        :percentage="getProgressPercentage(task)"
        :status="getProgressStatus(task?.status)"
      />
      <div class="progress-details">
        <span>{{ $t('migration.detail.progress.processedFiles') }}: {{ task?.processed_files || 0 }}/{{ task?.total_files || 0 }}</span>
        <span>{{ $t('migration.detail.progress.processedSize') }}: {{ formatSize(task?.processed_size || 0) }}/{{ formatSize(task?.total_size || 0) }}</span>
      </div>
    </div>
    
    <div class="file-list">
      <h2>{{ $t('migration.detail.fileList.title') }}</h2>
      <el-table 
        :data="fileStatuses" 
        v-loading="loading" 
        row-key="file_path"
        height="400"
        :max-height="400"
      >
        <el-table-column prop="file_path" :label="$t('migration.detail.fileList.filePath')" min-width="200" show-overflow-tooltip />
        <el-table-column prop="status" :label="$t('migration.detail.fileList.status')" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">
              {{ getStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="source_size" :label="$t('migration.detail.fileList.sourceSize')" width="120">
          <template #default="{ row }">
            {{ formatSize(row.source_size) }}
          </template>
        </el-table-column>
        <el-table-column prop="target_size" :label="$t('migration.detail.fileList.targetSize')" width="120">
          <template #default="{ row }">
            {{ formatSize(row.target_size) }}
          </template>
        </el-table-column>
        <el-table-column prop="error_message" :label="$t('migration.detail.fileList.errorMessage')" min-width="200" show-overflow-tooltip />
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
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { getMigrationTask, getMigrationFileStatuses } from '@/api/migration'
import { getStatusType, getStatusText, formatSize, getProgressPercentage, getProgressStatus } from '@/utils/migration'
import type { MigrationTask, MigrationFileStatus } from '@/types/migration'

const { t } = useI18n()
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
    const response = await getMigrationTask(route.params.id as string)
    if (response && typeof response === 'object' && !Array.isArray(response)) {
      // @ts-ignore
        task.value = response
    } else {
      ElMessage.error(t('migration.detail.message.loadTaskEmpty'))
    }
  } catch (error) {
    ElMessage.error(t('migration.detail.message.loadTaskError'))
  } finally {
    loading.value = false
  }
}

const loadFileStatuses = async () => {
  loading.value = true
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
  } catch (error) {
    ElMessage.error(t('migration.detail.message.loadFileStatusError'))
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
