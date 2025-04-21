<template>
  <div class="analysis-container">
    <el-card class="analysis-card">
      <template #header>
        <div class="card-header">
          <h2>{{ $t('analysis.title') }}</h2>
          <el-tooltip content="专业分析模式支持批量文件上传和自定义分析选项" placement="top">
            <el-tag type="success">专业模式</el-tag>
          </el-tooltip>
        </div>
      </template>

      <!-- 分析模板选择 -->
      <div class="analysis-options">
        <el-form :model="analysisForm" label-width="120px">
          <el-form-item label="分析模板">
            <el-select v-model="analysisForm.template" class="template-select">
              <el-option label="标准分析" value="standard" />
              <el-option label="深度分析" value="deep" />
              <el-option label="快速扫描" value="quick" />
              <el-option label="自定义模板" value="custom" />
            </el-select>
          </el-form-item>
          
          <!-- 自定义分析选项 -->
          <el-form-item label="分析选项">
            <el-checkbox-group v-model="analysisForm.options">
              <el-checkbox label="static">静态分析</el-checkbox>
              <el-checkbox label="dynamic">动态分析</el-checkbox>
              <el-checkbox label="network">网络行为分析</el-checkbox>
              <el-checkbox label="yara">Yara规则匹配</el-checkbox>
            </el-checkbox-group>
          </el-form-item>

          <el-form-item label="优先级">
            <el-radio-group v-model="analysisForm.priority">
              <el-radio label="high">高</el-radio>
              <el-radio label="normal">中</el-radio>
              <el-radio label="low">低</el-radio>
            </el-radio-group>
          </el-form-item>
        </el-form>
      </div>

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
            <h3>{{ $t('analysis.dropZone.title') }}</h3>
            <p>支持批量上传，最多{{ MAX_FILES }}个文件</p>
            <p>单个文件大小限制{{ formatFileSize(MAX_FILE_SIZE) }}</p>
            <p class="supported-types">支持的文件类型：EXE, DLL, PDF, DOC(X), XLS(X), ZIP, RAR等</p>
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
              开始分析 ({{ files.length }}/{{ MAX_FILES }})
            </el-button>
            <el-button @click="clearFiles">清空列表</el-button>
          </div>
        </div>
      </div>

      <!-- 分析队列 -->
      <div class="analysis-queue" v-if="analysisQueue.length">
        <h3>分析队列</h3>
        <el-table :data="analysisQueue" style="width: 100%">
          <el-table-column prop="fileName" label="文件名" />
          <el-table-column prop="status" label="状态">
            <template #default="scope">
              <el-tag :type="getStatusType(scope.row.status)">
                {{ scope.row.status }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="progress" label="进度">
            <template #default="scope">
              <el-progress :percentage="scope.row.progress" />
            </template>
          </el-table-column>
          <el-table-column label="操作" width="150">
            <template #default="scope">
              <el-button 
                size="small" 
                type="primary" 
                :disabled="scope.row.status !== 'completed'"
                @click="viewReport(scope.row)"
              >
                查看报告
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { Upload, Document, Delete } from '@element-plus/icons-vue'
import { analysisApi } from '@/api/analysis'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const MAX_FILES = 10
const MAX_FILE_SIZE = 100 * 1024 * 1024 // 100MB

const isDragging = ref(false)
const files = ref<File[]>([])
const uploading = ref(false)

interface AnalysisTask {
  fileName: string
  status: string
  progress: number
}

const analysisQueue = ref<AnalysisTask[]>([])

// 分析表单
const analysisForm = reactive({
  template: 'standard',
  options: ['static'],
  priority: 'normal'
})

// 状态样式映射
const getStatusType = (status: string) => {
  const map: Record<string, string> = {
    'pending': 'info',
    'processing': 'warning',
    'completed': 'success',
    'failed': 'danger'
  }
  return map[status] || 'info'
}

const handleDragOver = () => {
  isDragging.value = true
}

const handleDragLeave = () => {
  isDragging.value = false
}

const handleDrop = (e: DragEvent) => {
  isDragging.value = false
  const droppedFiles = Array.from(e.dataTransfer?.files || [])
  
  if (files.value.length + droppedFiles.length > MAX_FILES) {
    ElMessage.warning(t('analysis.message.maxFiles', { count: MAX_FILES }))
    return
  }
  
  const invalidFiles = droppedFiles.filter(file => file.size > MAX_FILE_SIZE)
  if (invalidFiles.length) {
    ElMessage.warning(t('analysis.message.maxFileSize', { files: invalidFiles.map(f => f.name).join(', ') }))
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
    ElMessage.warning(t('analysis.message.noFiles'))
    return
  }
  
  uploading.value = true
  try {
    // 将文件添加到分析队列
    const newTasks = files.value.map(file => ({
      fileName: file.name,
      status: 'pending',
      progress: 0
    }))
    analysisQueue.value.push(...newTasks)

    const response = await analysisApi.analyzeFiles(files.value)
    
    // 更新任务状态
    response.data.results.forEach((result, index) => {
      const task = newTasks[index]
      task.status = result.status === 'success' ? 'completed' : 'failed'
      task.progress = 100
    })
    
    clearFiles()
    ElMessage.success('文件已加入分析队列')
  } catch (error: any) {
    ElMessage.error(error.response?.data?.detail || t('analysis.message.analysisError'))
  } finally {
    uploading.value = false
  }
}

const viewReport = (task: any) => {
  // 实现查看报告的逻辑
  console.log('查看报告:', task)
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

.analysis-options {
  margin-bottom: 20px;
  padding: 20px;
  background-color: var(--el-bg-color-page);
  border-radius: 8px;
}

.template-select {
  width: 200px;
}

.drop-zone {
  flex: 1;
  border: 2px dashed var(--el-border-color);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
  transition: all 0.3s;
  min-height: 200px;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: var(--el-bg-color-page);
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
  color: var(--el-color-primary);
}

.upload-text h3 {
  margin: 0 0 10px;
  font-size: 20px;
  color: var(--el-text-color-primary);
}

.upload-text p {
  margin: 5px 0;
}

.supported-types {
  color: var(--el-text-color-secondary);
  font-size: 0.9em;
  margin-top: 10px;
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
  background-color: var(--el-bg-color);
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

.analysis-queue {
  margin-top: 20px;
  padding: 20px;
  background-color: var(--el-bg-color-page);
  border-radius: 8px;
}

.analysis-queue h3 {
  margin-top: 0;
  margin-bottom: 15px;
  color: var(--el-text-color-primary);
}
</style> 