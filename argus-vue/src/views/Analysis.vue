<template>
  <div class="analysis-container">
    <el-card class="analysis-card">
      <template #header>
        <div class="card-header">
          <h2>文件分析</h2>
        </div>
      </template>

      <div
        class="drop-zone"
        @drop.prevent="handleDrop"
        @dragover.prevent="handleDragOver"
        @dragleave.prevent="handleDragLeave"
        :class="{ 'drop-zone-active': isDragging }"
      >
        <div class="drop-content" v-if="!files.length">
          <el-icon class="upload-icon"><Upload /></el-icon>
          <div class="upload-text">
            <h3>拖放文件到此处进行分析</h3>
            <p>支持Windows PE可执行文件和所有文件类型</p>
            <p>最多10个文件，每个文件限制10MB</p>
          </div>
        </div>
        
        <div class="file-list" v-else>
          <div v-for="(file, index) in files" :key="index" class="file-item">
            <div class="file-info">
              <el-icon><Document /></el-icon>
              <span class="file-name">{{ file.name }}</span>
              <span class="file-size">({{ formatFileSize(file.size) }})</span>
            </div>
            <el-button
              type="danger"
              size="small"
              circle
              @click="removeFile(index)"
              class="remove-button"
            >
              <el-icon><Delete /></el-icon>
            </el-button>
          </div>
          
          <div class="upload-actions" v-if="files.length">
            <el-button type="primary" @click="startAnalysis" :loading="uploading">
              开始分析
            </el-button>
            <el-button @click="clearFiles">清空列表</el-button>
          </div>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Upload, Document, Delete } from '@element-plus/icons-vue'
import { analysisApi } from '@/api/analysis'

const MAX_FILES = 10
const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB

const isDragging = ref(false)
const files = ref<File[]>([])
const uploading = ref(false)

const handleDragOver = () => {
  isDragging.value = true
}

const handleDragLeave = () => {
  isDragging.value = false
}

const handleDrop = (e: DragEvent) => {
  isDragging.value = false
  const droppedFiles = Array.from(e.dataTransfer?.files || [])
  
  // 检查文件数量限制
  if (files.value.length + droppedFiles.length > MAX_FILES) {
    ElMessage.warning(`最多只能上传${MAX_FILES}个文件`)
    return
  }
  
  // 检查文件大小
  const invalidFiles = droppedFiles.filter(file => file.size > MAX_FILE_SIZE)
  if (invalidFiles.length) {
    ElMessage.warning(`以下文件超过大小限制(10MB)：${invalidFiles.map(f => f.name).join(', ')}`)
    return
  }
  
  files.value.push(...droppedFiles)
}

const removeFile = (index: number) => {
  files.value.splice(index, 1)
}

const clearFiles = () => {
  files.value = []
}

const formatFileSize = (bytes: number) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
}

const startAnalysis = async () => {
  if (!files.value.length) {
    ElMessage.warning('请先添加文件')
    return
  }
  
  uploading.value = true
  try {
    const response = await analysisApi.analyzeFiles(files.value)
    
    // 检查分析结果
    const successCount = response.data.results.filter(r => r.status === 'success').length
    const errorCount = response.data.results.filter(r => r.status === 'error').length
    
    if (errorCount > 0) {
      ElMessage.warning(`分析完成，${successCount}个成功，${errorCount}个失败`)
    } else {
      ElMessage.success('所有文件分析成功')
    }
    
    clearFiles()
  } catch (error: any) {
    ElMessage.error(error.response?.data?.detail || '分析失败，请重试')
  } finally {
    uploading.value = false
  }
}
</script>

<style scoped>
.analysis-container {
  padding: 20px;
  height: 100%;
  background-color: var(--el-bg-color);
}

.analysis-card {
  height: calc(100% - 40px);
  display: flex;
  flex-direction: column;
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

.drop-zone {
  flex: 1;
  border: 2px dashed var(--el-border-color);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
  transition: all 0.3s;
  min-height: 300px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.drop-zone-active {
  border-color: var(--el-color-primary);
  background-color: var(--el-color-primary-light-9);
}

.drop-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  color: var(--el-text-color-secondary);
}

.upload-icon {
  font-size: 48px;
  margin-bottom: 20px;
}

.upload-text h3 {
  margin: 0 0 10px;
  font-size: 20px;
  color: var(--el-text-color-primary);
}

.upload-text p {
  margin: 5px 0;
}

.file-list {
  width: 100%;
  max-width: 800px;
}

.file-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px;
  border: 1px solid var(--el-border-color);
  border-radius: 4px;
  margin-bottom: 10px;
  background-color: var(--el-bg-color-page);
}

.file-info {
  display: flex;
  align-items: center;
  gap: 10px;
}

.file-name {
  font-weight: 500;
}

.file-size {
  color: var(--el-text-color-secondary);
}

.upload-actions {
  margin-top: 20px;
  display: flex;
  gap: 10px;
  justify-content: center;
}
</style> 