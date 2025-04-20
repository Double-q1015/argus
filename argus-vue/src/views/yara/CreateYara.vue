<template>
  <div class="create-yara-container">
    <el-card class="yara-card">
      <template #header>
        <div class="card-header">
          <h2>{{ $t('yara.create.title') }}</h2>
        </div>
      </template>
      
      <el-form :model="yaraForm" :rules="rules" ref="yaraFormRef" label-width="200px">
        <el-form-item :label="$t('yara.create.name')" label-position="right">
          <el-input v-model="yaraForm.name" :placeholder="$t('yara.create.namePlaceholder')"></el-input>
        </el-form-item>
        
        <el-form-item :label="$t('yara.create.description')" label-position="right">
          <el-input
            v-model="yaraForm.description"
            type="textarea"
            :rows="3"
            :placeholder="$t('yara.create.descriptionPlaceholder')"
          ></el-input>
        </el-form-item>
        
        <el-form-item :label="$t('yara.create.content')" label-position="right">
          <el-input
            v-model="yaraForm.content"
            type="textarea"
            :rows="10"
            :placeholder="$t('yara.create.contentPlaceholder')"
            class="yara-content"
          ></el-input>
        </el-form-item>
        
        <el-form-item>
          <el-button type="primary" @click="submitForm">{{ $t('yara.create.submit') }}</el-button>
          <el-button @click="resetForm">{{ $t('yara.create.reset') }}</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import type { FormInstance, FormRules } from 'element-plus'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'
import { yaraApi } from '@/api/yara'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const router = useRouter()
const yaraFormRef = ref<FormInstance>()
const yaraForm = reactive({
  name: '',
  description: '',
  content: ''
})

const rules = reactive<FormRules>({
  name: [
    { required: true, message: t('yara.create.nameRules.required'), trigger: 'blur' },
    { min: 3, max: 50, message: t('yara.create.nameRules.length'), trigger: 'blur' }
  ],
  description: [
    { required: true, message: t('yara.create.descriptionRules.required'), trigger: 'blur' }
  ],
  content: [
    { required: true, message: t('yara.create.contentRules.required'), trigger: 'blur' }
  ]
})

const submitForm = async () => {
  if (!yaraFormRef.value) return
  
  await yaraFormRef.value.validate(async (valid) => {
    if (valid) {
      try {
        await yaraApi.createRule(yaraForm)
        ElMessage.success(t('yara.create.success'))
        router.push('/yara/list')
      } catch (error: any) {
        ElMessage.error(error.response?.data?.detail || t('yara.create.error'))
      }
    }
  })
}

const resetForm = () => {
  if (!yaraFormRef.value) return
  yaraFormRef.value.resetFields()
}
</script>

<style scoped>
.create-yara-container {
  padding: 20px;
  height: 100%;
  background-color: var(--el-bg-color);
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

.yara-content {
  font-family: monospace;
}
</style> 