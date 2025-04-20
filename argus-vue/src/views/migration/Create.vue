<template>
  <div class="migration-create">
    <div class="header">
      <h1>{{ $t('migration.create.title') }}</h1>
      <el-button @click="$router.push('/migration')">{{ $t('migration.create.back') }}</el-button>
    </div>
    
    <div class="form-container">
      <task-form @submit="handleSubmit" @cancel="$router.push('/migration')" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'
import TaskForm from '@/components/migration/TaskForm.vue'
import { createMigrationTask } from '@/api/migration'
import type { MigrationTaskCreate } from '@/types/migration'

const { t } = useI18n()
const router = useRouter()

const handleSubmit = async (data: MigrationTaskCreate) => {
  try {
    await createMigrationTask(data)
    ElMessage.success(t('migration.create.success'))
    router.push('/migration')
  } catch (error) {
    ElMessage.error(t('migration.create.error'))
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