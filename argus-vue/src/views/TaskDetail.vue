<template>
  <div class="task-detail-container">
    <el-card v-loading="loading" class="task-detail-card">
      <template #header>
        <div class="card-header">
          <div class="header-left">
            <h2>{{ task?.name }}</h2>
            <el-tag :type="getStatusType(task?.status)">
              {{ getStatusText(task?.status) }}
            </el-tag>
          </div>
          <div class="header-right">
            <el-button @click="goBack">返回</el-button>
            <el-button
              type="danger"
              @click="deleteTask"
              :disabled="task?.status === 'running'"
            >
              删除任务
            </el-button>
          </div>
        </div>
      </template>

      <el-descriptions :column="2" border>
        <el-descriptions-item label="任务ID">
          {{ task?.id }}
        </el-descriptions-item>
        <el-descriptions-item label="任务类型">
          {{ task?.type }}
        </el-descriptions-item>
        <el-descriptions-item label="优先级">
          {{ task?.priority }}
        </el-descriptions-item>
        <el-descriptions-item label="创建时间">
          {{ formatDate(task?.created_at) }}
        </el-descriptions-item>
        <el-descriptions-item label="更新时间">
          {{ formatDate(task?.updated_at) }}
        </el-descriptions-item>
        <el-descriptions-item label="创建者">
          {{ task?.created_by }}
        </el-descriptions-item>
        <el-descriptions-item label="描述" :span="2">
          {{ task?.description || '无' }}
        </el-descriptions-item>
      </el-descriptions>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { tasksApi, type Task, type TaskStatus } from '@/api/tasks'
import { formatDate } from '@/utils/date'

const route = useRoute()
const router = useRouter()
const loading = ref(false)
const task = ref<Task | null>(null)
const taskStatus = ref<TaskStatus | null>(null)

const loadTask = async () => {
  const taskId = route.params.id as string
  if (!taskId) return

  loading.value = true
  try {
    // 获取任务详情
    const taskData = await tasksApi.getTask(taskId)
    task.value = taskData
  } catch (error: any) {
    ElMessage.error(error.response?.data?.detail || '获取任务详情失败')
  } finally {
    loading.value = false
  }
}

const getStatusType = (status?: string) => {
  const types: Record<string, string> = {
    created: 'info',
    pending: 'warning',
    running: 'primary',
    completed: 'success',
    failed: 'danger'
  }
  return types[status || ''] || 'info'
}

const getStatusText = (status?: string) => {
  const texts: Record<string, string> = {
    created: '已创建',
    pending: '等待中',
    running: '运行中',
    completed: '已完成',
    failed: '失败'
  }
  return texts[status || ''] || status
}

const goBack = () => {
  router.back()
}

const deleteTask = async () => {
  if (!task.value) return

  try {
    await ElMessageBox.confirm(
      `确定要删除任务"${task.value.name}"吗？`,
      '删除确认',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
    
    await tasksApi.deleteTask(task.value.id)
    ElMessage.success('删除成功')
    router.push('/tasks')
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error(error.response?.data?.detail || '删除失败')
    }
  }
}

onMounted(() => {
  loadTask()
})
</script>

<style scoped>
.task-detail-container {
  padding: 20px;
  height: 100%;
  background-color: var(--el-bg-color);
}

.task-detail-card {
  height: calc(100% - 40px);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.header-left h2 {
  margin: 0;
  color: var(--el-text-color-primary);
}

.header-right {
  display: flex;
  gap: 12px;
}

.task-status {
  margin-top: 24px;
}

.task-status h3 {
  margin: 0 0 16px;
  color: var(--el-text-color-primary);
}

.failed-sample-tag {
  margin-right: 8px;
  margin-bottom: 8px;
}
</style> 