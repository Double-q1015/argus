<template>
    <div class="upload-container">
      <!-- VirusTotal Upload Card -->
      <el-card class="mb-4">
        <template #header>
          <div class="card-header">
            <span>VirusTotal Upload</span>
          </div>
        </template>
        
        <VirusTotalUploader @success="handleVtSuccess" />
      </el-card>

      <!-- Local File Upload Card -->
      <el-card class="mb-4">
        <template #header>
          <div class="card-header">
            <span>Local File Upload</span>
          </div>
        </template>
        
        <LocalUploder @success="handleLocalSuccess" />
      </el-card>
    </div>
  </template>
  
<script setup lang="ts">
import { ElMessage } from 'element-plus'
import { useQueryClient } from '@tanstack/vue-query'
import VirusTotalUploader from './VirusTotalUploader.vue'
import LocalUploder from './LocalUploder.vue'
const queryClient = useQueryClient()

const handleVtSuccess = () => {
queryClient.invalidateQueries({ queryKey: ['recentSamples'] })
queryClient.invalidateQueries({ queryKey: ['mimeTypeStats'] })
}

const handleLocalSuccess = (response: any, file: any) => {
ElMessage.success(`${file.name} Upload successfully`)
queryClient.invalidateQueries({ queryKey: ['recentSamples'] })
}

</script>

<style scoped>
.upload-container {
margin-bottom: 20px;
}

.upload-form, .vt-form {
max-width: 500px;
margin: 0 auto;
}

.mt-3 {
margin-top: 12px;
}

.mb-3 {
margin-bottom: 12px;
}

.mb-4 {
margin-bottom: 16px;
}
</style>