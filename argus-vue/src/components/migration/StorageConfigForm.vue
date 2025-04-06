<template>
  <div class="storage-config-form">
    <template v-if="storageType === 'minio'">
      <el-form-item label="端点" prop="endpoint">
        <el-input v-model="config.endpoint" placeholder="例如: localhost:9000" />
      </el-form-item>
      <el-form-item label="访问密钥" prop="access_key">
        <el-input v-model="config.access_key" />
      </el-form-item>
      <el-form-item label="密钥" prop="secret_key">
        <el-input v-model="config.secret_key" type="password" show-password />
      </el-form-item>
      <el-form-item label="存储桶" prop="bucket_name">
        <el-input v-model="config.bucket_name" />
      </el-form-item>
      <el-form-item label="路径前缀" prop="prefix">
        <el-input v-model="config.prefix" placeholder="可选，例如: samples/" />
      </el-form-item>
      <el-form-item label="使用HTTPS" prop="secure">
        <el-switch v-model="config.secure" />
      </el-form-item>
    </template>
    
    <template v-else-if="storageType === 'local'">
      <el-form-item label="基础路径" prop="base_path">
        <el-input v-model="config.base_path" placeholder="例如: /data/samples" />
      </el-form-item>
      <el-form-item label="目录深度" prop="directory_depth">
        <el-input-number v-model="config.directory_depth" :min="0" :max="4" />
      </el-form-item>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, watch } from 'vue'
import type { MinioStorageConfig, LocalStorageConfig } from '@/types/migration'

const props = defineProps<{
  modelValue: Record<string, any>
  storageType: 'minio' | 'local'
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: Record<string, any>): void
}>()

// 初始化配置对象
const initConfig = () => {
  if (props.storageType === 'minio') {
    return {
      endpoint: '',
      access_key: '',
      secret_key: '',
      bucket_name: '',
      prefix: '',
      secure: false
    }
  } else {
    return {
      base_path: '',
      directory_depth: 2
    }
  }
}

// 监听存储类型变化，重新初始化配置
watch(() => props.storageType, () => {
  emit('update:modelValue', initConfig())
}, { immediate: true })

const config = computed<Record<string, any>>({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value)
})
</script>

<style scoped>
.storage-config-form {
  padding: 1rem;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
}
</style> 