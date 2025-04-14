<template>
  <div class="task-list-container">
    <el-card class="task-list-card">
      <template #header>
        <div class="card-header">
          <h2>任务列表</h2>
          <el-button type="primary" @click="createTask">创建任务</el-button>
        </div>
      </template>

      <el-table
        v-loading="loading"
        :data="tasks"
        style="width: 100%"
        @row-click="handleRowClick"
      >
        <el-table-column prop="name" label="任务名称" min-width="200" />
        <el-table-column prop="type" label="任务类型" width="120">
          <template #default="{ row }">
            <el-tag :type="getTaskTypeTag(row.type)">
              {{ row.type }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">
              {{ getStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="priority" label="优先级" width="80" />
        <el-table-column prop="created_at" label="创建时间" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column prop="updated_at" label="更新时间" width="180">
          <template #default="{ row }">
            {{ formatDate(row.updated_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button
              type="primary"
              link
              @click.stop="viewTask(row)"
            >
              查看
            </el-button>
            <el-button
              type="success"
              link
              @click.stop="startTask(row)"
              :disabled="row.status !== 'created'"
            >
              启动
            </el-button>
            <el-button
              type="danger"
              link
              @click.stop="deleteTask(row)"
              :disabled="row.status === 'running'"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination-container">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { tasksApi, type Task } from '@/api/tasks'
import { formatDate } from '@/utils/date'

const router = useRouter()
const loading = ref(false)
const tasks = ref<Task[]>([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)

const loadTasks = async () => {
  loading.value = true
  try {
    const skip = (currentPage.value - 1) * pageSize.value
    const response = await tasksApi.getTasks({
      skip,
      limit: pageSize.value
    })
    tasks.value = response
    total.value = response.length
  } catch (error: any) {
    ElMessage.error(error.response?.data?.detail || '获取任务列表失败')
  } finally {
    loading.value = false
  }
}

const getStatusType = (status: string) => {
  const types: Record<string, string> = {
    created: 'info',
    pending: 'warning',
    running: 'primary',
    completed: 'success',
    failed: 'danger'
  }
  return types[status] || 'info'
}

const getStatusText = (status: string) => {
  const texts: Record<string, string> = {
    created: '已创建',
    pending: '等待中',
    running: '运行中',
    completed: '已完成',
    failed: '失败'
  }
  return texts[status] || status
}

const getTaskTypeTag = (type: string) => {
  const types: Record<string, string> = {
    'hash': 'danger',
    'pe_info': 'warning',
    'service_scan': 'success',
    'os_detection': 'info',
    'web_scan': 'primary'
  }
  return types[type] || 'default'
}

const handleRowClick = (row: Task) => {
  viewTask(row)
}

const viewTask = (task: Task) => {
  router.push(`/tasks/${task.id}`)
}

const createTask = () => {
  router.push('/tasks/create')
}

const deleteTask = async (task: Task) => {
  try {
    await ElMessageBox.confirm(
      `确定要删除任务"${task.name}"吗？`,
      '删除确认',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
    
    await tasksApi.deleteTask(task.id)
    ElMessage.success('删除成功')
    loadTasks()
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error(error.response?.data?.detail || '删除失败')
    }
  }
}

const startTask = async (task: Task) => {
  try {
    await tasksApi.startTask(task.id)
    ElMessage.success('任务已启动')
    loadTasks()
  } catch (error: any) {
    ElMessage.error(error.response?.data?.detail || '启动任务失败')
  }
}

const handleSizeChange = (val: number) => {
  pageSize.value = val
  loadTasks()
}

const handleCurrentChange = (val: number) => {
  currentPage.value = val
  loadTasks()
}

onMounted(() => {
  loadTasks()
})
</script>

<style scoped>
.task-list-container {
  padding: 20px;
  height: 100%;
  background-color: var(--el-bg-color);
}

.task-list-card {
  height: calc(100% - 40px);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h2 {
  margin: 0;
  color: var(--el-text-color-primary);
}

.pagination-container {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}
</style> 