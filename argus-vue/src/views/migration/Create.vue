<template>
  <div class="migration-create">
    <div class="header">
      <h1>创建迁移任务</h1>
      <el-button @click="$router.push('/migration')">返回</el-button>
    </div>
    
    <div class="form-container">
      <task-form @submit="handleSubmit" @cancel="$router.push('/migration')" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'
import TaskForm from '@/components/migration/TaskForm.vue'
import { createMigrationTask } from '@/api/migration'
import type { MigrationTaskCreate } from '@/types/migration'

const router = useRouter()

const handleSubmit = async (data: MigrationTaskCreate) => {
  try {
    await createMigrationTask(data)
    ElMessage.success('创建迁移任务成功')
    router.push('/migration')
  } catch (error) {
    ElMessage.error('创建迁移任务失败')
  }
}
</script>

<style scoped>
.migration-create {
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

.form-container {
  padding: 20px;
  background-color: #fff;
  border-radius: 4px;
  box-shadow: 0 2px 12px 0 rgba(0,0,0,0.1);
}
</style> 