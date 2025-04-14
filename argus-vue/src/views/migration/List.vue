<template>
  <div class="migration-list">
    <div class="header">
      <h1>数据迁移</h1>
      <el-button type="primary" @click="$router.push('/migration/create')">
        创建迁移任务
      </el-button>
    </div>
    
    <el-table :data="tasks" v-loading="loading">
      <el-table-column prop="name" label="任务名称" />
      <el-table-column prop="source_storage" label="源存储" />
      <el-table-column prop="target_storage" label="目标存储" />
      <el-table-column prop="status" label="状态">
        <template #default="{ row }">
          <el-tag :type="getStatusType(row.status)">
            {{ getStatusText(row.status) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="created_at" label="创建时间" />
      <el-table-column label="操作" width="200">
        <template #default="{ row }">
          <el-button-group>
            <el-button 
              size="small"
              @click="$router.push(`/migration/${row.id}`)"
            >
              详情
            </el-button>
            <el-button 
              v-if="row.status === 'pending'"
              type="primary"
              size="small"
              @click="handleExecute(row)"
            >
              执行
            </el-button>
            <el-button 
              v-if="['pending', 'running'].includes(row.status)"
              type="warning"
              size="small"
              @click="handleCancel(row)"
            >
              取消
            </el-button>
            <el-button 
              v-if="['completed', 'failed', 'cancelled'].includes(row.status)"
              type="danger"
              size="small"
              @click="handleDelete(row)"
            >
              删除
            </el-button>
          </el-button-group>
        </template>
      </el-table-column>
    </el-table>
    
    <el-pagination
      v-model:current-page="currentPage"
      v-model:page-size="pageSize"
      :total="total"
      @current-change="loadTasks"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getMigrationTasks, executeMigrationTask, cancelMigrationTask, deleteMigrationTask } from '@/api/migration'
import { getStatusType, getStatusText } from '@/utils/migration'
import type { MigrationTask } from '@/types/migration'

const loading = ref(false)
const tasks = ref<MigrationTask[]>([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)

const loadTasks = async () => {
  loading.value = true
  try {
    const skip = (currentPage.value - 1) * pageSize.value
    const response = await getMigrationTasks({
      skip,
      limit: pageSize.value
    })
    // @ts-ignore
    tasks.value = response.data
    // @ts-ignore
    total.value = response.total || 0
  } catch (error) {
    ElMessage.error('加载迁移任务失败')
  } finally {
    loading.value = false
  }
}

const handleExecute = async (task: MigrationTask) => {
  try {
    await executeMigrationTask(task.id)
    ElMessage.success('开始执行迁移任务')
    loadTasks()
  } catch (error) {
    ElMessage.error('执行迁移任务失败')
  }
}

const handleCancel = async (task: MigrationTask) => {
  try {
    await ElMessageBox.confirm('确定要取消该迁移任务吗？', '提示', {
      type: 'warning'
    })
    await cancelMigrationTask(task.id)
    ElMessage.success('已取消迁移任务')
    loadTasks()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('取消迁移任务失败')
    }
  }
}

const handleDelete = async (task: MigrationTask) => {
  try {
    await ElMessageBox.confirm('确定要删除该迁移任务吗？', '提示', {
      type: 'warning'
    })
    await deleteMigrationTask(task.id)
    ElMessage.success('已删除迁移任务')
    loadTasks()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('删除迁移任务失败')
    }
  }
}

onMounted(() => {
  loadTasks()
})
</script>

<style scoped>
.migration-list {
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

.el-pagination {
  margin-top: 20px;
  justify-content: flex-end;
}
</style> 