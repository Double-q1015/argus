<template>
  <div class="quick-upload">
    <el-card class="upload-card">
      <template #header>
        <div class="card-header">
          <span>快速分析</span>
          <el-tooltip content="拖拽文件到此处进行快速分析" placement="top">
            <el-tag type="info">单文件分析</el-tag>
          </el-tooltip>
        </div>
      </template>

      <div
        class="drop-zone"
        @drop.prevent="handleDrop"
        @dragover.prevent="handleDragOver"
        @dragleave.prevent="handleDragLeave"
        :class="{ 'drop-zone-active': isDragging }"
      >
        <div v-if="!currentFile" class="upload-placeholder">
          <el-icon class="upload-icon"><Upload /></el-icon>
          <div class="upload-text">
            <p>拖拽文件到此处</p>
            <p class="sub-text">或点击选择文件进行快速分析</p>
          </div>
          <input
            type="file"
            ref="fileInput"
            style="display: none"
            @change="handleFileSelect"
          />
          <el-button type="primary" @click="triggerFileSelect">选择文件</el-button>
        </div>

        <div v-else class="file-info">
          <div class="file-details">
            <el-icon class="file-icon"><Document /></el-icon>
            <div class="file-text">
              <span class="file-name">{{ currentFile.name }}</span>
              <span class="file-size">{{ formatFileSize(currentFile.size) }}</span>
            </div>
          </div>
          <div class="file-actions">
            <el-button type="primary" @click="startQuickAnalysis" :loading="analyzing">
              快速分析
            </el-button>
            <el-button @click="clearFile" plain>取消</el-button>
          </div>
        </div>
      </div>

      <!-- 最近分析历史 -->
      <div class="recent-analysis" v-if="recentAnalysis.length">
        <div class="section-header">
          <h4>最近分析</h4>
          <el-button link type="primary" @click="viewAllHistory">查看全部</el-button>
        </div>
        <div class="history-list">
          <div v-for="item in recentAnalysis.slice(0, 3)" :key="item.id" class="history-item">
            <div class="history-info">
              <el-icon><Document /></el-icon>
              <span class="history-filename">{{ item.fileName }}</span>
              <el-tag size="small" :type="item.result === 'safe' ? 'success' : 'danger'">
                {{ item.result === 'safe' ? '安全' : '危险' }}
              </el-tag>
            </div>
            <span class="history-time">{{ formatTime(item.time) }}</span>
          </div>
        </div>
      </div>

      <!-- 快速分析模板 -->
      <div class="analysis-templates">
        <div class="section-header">
          <h4>快速分析模板</h4>
        </div>
        <div class="template-list">
          <el-row :gutter="20">
            <el-col :span="8" v-for="template in templates" :key="template.id">
              <div class="template-item" @click="useTemplate(template)">
                <el-icon class="template-icon"><component :is="template.icon" /></el-icon>
                <div class="template-info">
                  <h5>{{ template.name }}</h5>
                  <p>{{ template.description }}</p>
                </div>
              </div>
            </el-col>
          </el-row>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Upload, Document} from '@element-plus/icons-vue'
import { format } from 'date-fns'

const MAX_FILE_SIZE = 50 * 1024 * 1024 // 50MB
const isDragging = ref(false)
const currentFile = ref<File | null>(null)
const analyzing = ref(false)
const fileInput = ref<HTMLInputElement | null>(null)

// 模拟最近分析历史
const recentAnalysis = ref([
  { id: 1, fileName: 'test.exe', result: 'safe', time: new Date(2024, 3, 20, 14, 30) },
  { id: 2, fileName: 'document.pdf', result: 'dangerous', time: new Date(2024, 3, 20, 13, 15) },
  { id: 3, fileName: 'sample.dll', result: 'safe', time: new Date(2024, 3, 20, 12, 45) }
])

// 分析模板
const templates = [
  {
    id: 1,
    name: '恶意软件检测',
    description: '检测可执行文件是否包含恶意代码',
    icon: 'Warning'
  },
  {
    id: 2,
    name: '文档安全检查',
    description: '检查文档文件中的潜在威胁',
    icon: 'Shield'
  },
  {
    id: 3,
    name: '行为分析',
    description: '分析程序运行时的行为特征',
    icon: 'Monitor'
  }
]

const handleDragOver = () => {
  isDragging.value = true
}

const handleDragLeave = () => {
  isDragging.value = false
}

const handleDrop = (e: DragEvent) => {
  isDragging.value = false
  const files = e.dataTransfer?.files
  if (files && files.length > 0) {
    validateAndSetFile(files[0])
  }
}

const triggerFileSelect = () => {
  fileInput.value?.click()
}

const handleFileSelect = (e: Event) => {
  const files = (e.target as HTMLInputElement).files
  if (files && files.length > 0) {
    validateAndSetFile(files[0])
  }
}

const validateAndSetFile = (file: File) => {
  if (file.size > MAX_FILE_SIZE) {
    ElMessage.warning(`文件大小不能超过 ${formatFileSize(MAX_FILE_SIZE)}`)
    return
  }
  currentFile.value = file
}

const clearFile = () => {
  currentFile.value = null
  if (fileInput.value) {
    fileInput.value.value = ''
  }
}

const startQuickAnalysis = async () => {
  if (!currentFile.value) return
  
  analyzing.value = true
  try {
    // TODO: 实现快速分析逻辑
    await new Promise(resolve => setTimeout(resolve, 2000)) // 模拟分析过程
    ElMessage.success('分析完成')
    clearFile()
  } catch (error) {
    ElMessage.error('分析失败')
  } finally {
    analyzing.value = false
  }
}

const formatFileSize = (bytes: number) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
}

const formatTime = (date: Date) => {
  return format(date, 'HH:mm')
}

const viewAllHistory = () => {
  // TODO: 实现查看全部历史记录的逻辑
}

const useTemplate = (template: typeof templates[0]) => {
  // TODO: 实现使用模板的逻辑
  ElMessage.info(`使用模板: ${template.name}`)
}
</script>

<style scoped>
.quick-upload {
  margin-bottom: 20px;
}

.upload-card {
  background-color: var(--el-bg-color);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.drop-zone {
  border: 2px dashed var(--el-border-color);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
  transition: all 0.3s;
  min-height: 150px;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: var(--el-bg-color-page);
  margin-bottom: 20px;
}

.drop-zone-active {
  border-color: var(--el-color-primary);
  background-color: var(--el-color-primary-light-9);
}

.upload-placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
}

.upload-icon {
  font-size: 40px;
  color: var(--el-color-primary);
}

.upload-text {
  margin: 10px 0;
}

.sub-text {
  color: var(--el-text-color-secondary);
  font-size: 0.9em;
}

.file-info {
  width: 100%;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.file-details {
  display: flex;
  align-items: center;
  gap: 10px;
}

.file-icon {
  font-size: 24px;
  color: var(--el-color-primary);
}

.file-text {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
}

.file-name {
  font-weight: 500;
}

.file-size {
  color: var(--el-text-color-secondary);
  font-size: 0.9em;
}

.file-actions {
  display: flex;
  gap: 10px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.section-header h4 {
  margin: 0;
  color: var(--el-text-color-primary);
}

.history-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.history-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px;
  background-color: var(--el-bg-color-page);
  border-radius: 4px;
}

.history-info {
  display: flex;
  align-items: center;
  gap: 10px;
}

.history-filename {
  font-weight: 500;
}

.history-time {
  color: var(--el-text-color-secondary);
  font-size: 0.9em;
}

.template-list {
  margin-top: 15px;
}

.template-item {
  padding: 15px;
  background-color: var(--el-bg-color-page);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.3s;
}

.template-item:hover {
  transform: translateY(-2px);
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
}

.template-icon {
  font-size: 24px;
  color: var(--el-color-primary);
  margin-bottom: 10px;
}

.template-info h5 {
  margin: 0 0 5px;
  color: var(--el-text-color-primary);
}

.template-info p {
  margin: 0;
  color: var(--el-text-color-secondary);
  font-size: 0.9em;
}

.recent-analysis {
  margin-bottom: 20px;
}

.analysis-templates {
  margin-top: 20px;
}
</style> 