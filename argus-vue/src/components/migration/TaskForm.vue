<template>
  <el-form 
    ref="formRef"
    :model="form"
    :rules="rules"
    label-width="120px"
  >
    <el-form-item label="任务名称" prop="name">
      <el-input v-model="form.name" />
    </el-form-item>
    
    <el-form-item label="描述" prop="description">
      <el-input 
        v-model="form.description"
        type="textarea"
        :rows="3"
      />
    </el-form-item>
    
    <el-form-item label="源存储" prop="source_storage">
      <el-select v-model="form.source_storage">
        <el-option label="MinIO" value="minio" />
        <el-option label="本地存储" value="local" />
      </el-select>
    </el-form-item>
    
    <el-form-item label="源存储配置" prop="source_config">
      <storage-config-form
        v-model="form.source_config"
        :storage-type="form.source_storage"
      />
    </el-form-item>
    
    <el-form-item label="目标存储" prop="target_storage">
      <el-select v-model="form.target_storage">
        <el-option label="MinIO" value="minio" />
        <el-option label="本地存储" value="local" />
      </el-select>
    </el-form-item>
    
    <el-form-item label="目标存储配置" prop="target_config">
      <storage-config-form
        v-model="form.target_config"
        :storage-type="form.target_storage"
      />
    </el-form-item>
    
    <el-form-item label="文件匹配模式" prop="file_patterns">
      <el-select
        v-model="form.file_patterns"
        multiple
        filterable
        allow-create
        default-first-option
        placeholder="请输入文件匹配模式"
      >
        <el-option
          v-for="pattern in commonPatterns"
          :key="pattern"
          :label="pattern"
          :value="pattern"
        />
      </el-select>
    </el-form-item>
    
    <el-form-item>
      <el-button type="primary" @click="submitForm">创建</el-button>
      <el-button @click="$emit('cancel')">取消</el-button>
    </el-form-item>
  </el-form>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import type { FormInstance } from 'element-plus'
import StorageConfigForm from './StorageConfigForm.vue'
import type { MigrationTaskCreate, MinioStorageConfig, LocalStorageConfig } from '@/types/migration'

const props = defineProps<{
  initialData?: Partial<MigrationTaskCreate>
}>()

const emit = defineEmits<{
  (e: 'submit', data: MigrationTaskCreate): void
  (e: 'cancel'): void
}>()

const formRef = ref<FormInstance>()
const form = reactive<MigrationTaskCreate>({
  name: '',
  description: '',
  source_storage: 'minio',
  source_config: {
    endpoint: '',
    access_key: '',
    secret_key: '',
    bucket_name: '',
    prefix: '',
    secure: false
  } as MinioStorageConfig,
  target_storage: 'local',
  target_config: {
    base_path: '',
    directory_depth: 2
  } as LocalStorageConfig,
  file_patterns: [],
  ...props.initialData
})

const commonPatterns = [
  '*.exe',
  '*.dll',
  '*.pdf',
  '*.doc',
  '*.docx',
  '*.xls',
  '*.xlsx',
  '*.txt',
  '*.json',
  '*.xml'
]

const rules = {
  name: [
    { required: true, message: '请输入任务名称', trigger: 'blur' },
    { min: 2, max: 50, message: '长度在 2 到 50 个字符', trigger: 'blur' }
  ],
  source_storage: [
    { required: true, message: '请选择源存储类型', trigger: 'change' }
  ],
  target_storage: [
    { required: true, message: '请选择目标存储类型', trigger: 'change' }
  ],
  source_config: [
    { required: true, message: '请配置源存储', trigger: 'change' }
  ],
  target_config: [
    { required: true, message: '请配置目标存储', trigger: 'change' }
  ]
}

const submitForm = async () => {
  if (!formRef.value) return
  
  await formRef.value.validate((valid) => {
    if (valid) {
      emit('submit', { ...form })
    }
  })
}
</script> 