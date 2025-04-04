<template>
  <div class="samples-container">
    <div class="header">
      <h1>样本管理</h1>
      <el-button type="primary" @click="showUploadDialog = true">
        上传样本
      </el-button>
    </div>

    <!-- 搜索栏 -->
    <div class="search-bar">
      <el-input
        v-model="searchQuery"
        placeholder="搜索样本..."
        class="search-input"
        clearable
        @clear="handleSearch"
        @keyup.enter="handleSearch"
      >
        <template #prefix>
          <el-icon><Search /></el-icon>
        </template>
      </el-input>
    </div>

    <!-- 样本列表 -->
    <el-table
      v-loading="loading"
      :data="samples"
      style="width: 100%"
      border
    >
      <el-table-column prop="file_name" label="文件名" />
      <el-table-column prop="sha256_digest" label="SHA256" width="280" />
      <el-table-column prop="file_size" label="大小" width="120">
        <template #default="{ row }">
          {{ formatFileSize(row.file_size) }}
        </template>
      </el-table-column>
      <el-table-column prop="file_type" label="类型" width="120" />
      <el-table-column prop="upload_time" label="上传时间" width="180">
        <template #default="{ row }">
          {{ formatDate(row.upload_time) }}
        </template>
      </el-table-column>
      <el-table-column prop="analysis_status" label="分析状态" width="120">
        <template #default="{ row }">
          <el-tag :type="getStatusType(row.analysis_status)">
            {{ row.analysis_status }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="200" fixed="right">
        <template #default="{ row }">
          <el-button-group>
            <el-button
              size="small"
              type="primary"
              @click="viewDetails(row)"
            >
              详情
            </el-button>
            <el-button
              size="small"
              type="success"
              @click="handleDownload(row)"
              :loading="row.downloading"
            >
              下载
            </el-button>
            <el-button
              size="small"
              type="danger"
              @click="handleDelete(row)"
            >
              删除
            </el-button>
          </el-button-group>
        </template>
      </el-table-column>
    </el-table>

    <!-- 分页 -->
    <div class="pagination">
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50, 100]"
        :total="total"
        layout="total, sizes, prev, pager, next"
        @size-change="handleSizeChange"
        @current-change="handleCurrentChange"
      />
    </div>

    <!-- 上传对话框 -->
    <el-dialog
      v-model="showUploadDialog"
      title="上传样本"
      width="500px"
    >
      <el-form
        ref="uploadForm"
        :model="uploadForm"
        :rules="uploadRules"
        label-width="100px"
      >
        <el-form-item label="文件" prop="file">
          <el-upload
            class="upload-demo"
            drag
            action="#"
            :auto-upload="false"
            :on-change="handleFileChange"
          >
            <el-icon class="el-icon--upload"><upload-filled /></el-icon>
            <div class="el-upload__text">
              拖拽文件到此处或 <em>点击上传</em>
            </div>
          </el-upload>
        </el-form-item>
        <el-form-item label="标签" prop="tags">
          <el-select
            v-model="uploadForm.tags"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="请选择或创建标签"
          >
            <el-option
              v-for="tag in availableTags"
              :key="tag"
              :label="tag"
              :value="tag"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input
            v-model="uploadForm.description"
            type="textarea"
            :rows="3"
            placeholder="请输入样本描述"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="showUploadDialog = false">取消</el-button>
          <el-button type="primary" @click="handleUpload" :loading="uploading">
            上传
          </el-button>
        </span>
      </template>
    </el-dialog>

    <!-- 详情对话框 -->
    <el-dialog
      v-model="showDetailsDialog"
      title="样本详情"
      width="800px"
    >
      <el-descriptions :column="2" border>
        <el-descriptions-item label="文件名">
          {{ selectedSample?.file_name }}
        </el-descriptions-item>
        <el-descriptions-item label="SHA256">
          {{ selectedSample?.sha256_digest }}
        </el-descriptions-item>
        <el-descriptions-item label="文件大小">
          {{ formatFileSize(selectedSample?.file_size) }}
        </el-descriptions-item>
        <el-descriptions-item label="文件类型">
          {{ selectedSample?.file_type }}
        </el-descriptions-item>
        <el-descriptions-item label="上传时间">
          {{ formatDate(selectedSample?.upload_time) }}
        </el-descriptions-item>
        <el-descriptions-item label="上传者">
          {{ selectedSample?.uploader }}
        </el-descriptions-item>
        <el-descriptions-item label="分析状态">
          <el-tag :type="getStatusType(selectedSample?.analysis_status)">
            {{ selectedSample?.analysis_status }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="标签">
          <el-tag
            v-for="tag in selectedSample?.tags"
            :key="tag"
            class="mx-1"
            style="margin-right: 5px"
          >
            {{ tag }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>
      
      <div v-if="selectedSample?.description" class="description-section">
        <h3>描述</h3>
        <p>{{ selectedSample.description }}</p>
      </div>

      <div v-if="selectedSample?.analysis_results" class="analysis-section">
        <h3>分析结果</h3>
        <pre>{{ JSON.stringify(selectedSample.analysis_results, null, 2) }}</pre>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search, UploadFilled } from '@element-plus/icons-vue'
import { getSamples, uploadSample, deleteSample, downloadSample } from '@/api/samples'
import type { Sample } from '@/types/sample'
import type { ApiListResponse } from '@/utils/request'

// 扩展Sample类型，添加downloading属性
interface SampleWithDownloading extends Sample {
  downloading?: boolean;
}

// 状态变量
const loading = ref(false)
const samples = ref<SampleWithDownloading[]>([])
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(10)
const searchQuery = ref('')
const showUploadDialog = ref(false)
const showDetailsDialog = ref(false)
const uploading = ref(false)
const selectedSample = ref<Sample | null>(null)

// 上传表单
const uploadForm = ref({
  file: null as File | null,
  tags: [] as string[],
  description: ''
})

// 表单验证规则
const uploadRules = {
  file: [
    { required: true, message: '请选择文件', trigger: 'change' }
  ]
}

// 可用标签列表
const availableTags = ref<string[]>([])

// 获取样本列表
const fetchSamples = async () => {
  loading.value = true
  try {
    const response = await getSamples({
      skip: (currentPage.value - 1) * pageSize.value,
      limit: pageSize.value,
      search: searchQuery.value
    })
    const data = response as unknown as ApiListResponse<Sample>
    samples.value = data.data.map(sample => ({
      ...sample,
      downloading: false
    }))
    total.value = data.total
  } catch (error) {
    console.error('Failed to fetch samples:', error)
    ElMessage.error('获取样本列表失败')
  } finally {
    loading.value = false
  }
}

// 处理文件上传
const handleFileChange = (file: any) => {
  uploadForm.value.file = file.raw
}

// 处理上传
const handleUpload = async () => {
  if (!uploadForm.value.file) {
    ElMessage.warning('请选择文件')
    return
  }

  uploading.value = true
  try {
    await uploadSample({
      file: uploadForm.value.file,
      tags: uploadForm.value.tags,
      description: uploadForm.value.description
    })
    ElMessage.success('上传成功')
    showUploadDialog.value = false
    fetchSamples()
  } catch (error) {
    ElMessage.error('上传失败')
  } finally {
    uploading.value = false
  }
}

// 处理删除
const handleDelete = async (sample: Sample) => {
  try {
    await ElMessageBox.confirm(
      '确定要删除这个样本吗？',
      '警告',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
    await deleteSample(sample.sha256_digest)
    ElMessage.success('删除成功')
    fetchSamples()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('删除失败')
    }
  }
}

// 查看详情
const viewDetails = (sample: Sample) => {
  selectedSample.value = sample
  showDetailsDialog.value = true
}

// 处理搜索
const handleSearch = () => {
  currentPage.value = 1
  fetchSamples()
}

// 处理分页
const handleSizeChange = (val: number) => {
  pageSize.value = val
  fetchSamples()
}

const handleCurrentChange = (val: number) => {
  currentPage.value = val
  fetchSamples()
}

// 格式化文件大小
const formatFileSize = (size: number | undefined) => {
  if (!size) return '0 B'
  if (size < 1024) return size + ' B'
  if (size < 1024 * 1024) return (size / 1024).toFixed(2) + ' KB'
  if (size < 1024 * 1024 * 1024) return (size / (1024 * 1024)).toFixed(2) + ' MB'
  return (size / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
}

// 格式化日期
const formatDate = (date: string | undefined) => {
  if (!date) return '-'
  return new Date(date).toLocaleString()
}

// 获取状态类型
const getStatusType = (status: string | undefined) => {
  if (!status) return ''
  switch (status) {
    case 'pending':
      return 'info'
    case 'analyzing':
      return 'warning'
    case 'completed':
      return 'success'
    case 'failed':
      return 'danger'
    default:
      return ''
  }
}

// 处理下载
const handleDownload = async (sample: SampleWithDownloading) => {
  try {
    sample.downloading = true
    const response = await downloadSample(sample.sha256_digest)
    
    // 创建一个临时的 a 标签来触发下载
    const link = document.createElement('a')
    link.href = response.data.download_url
    link.download = sample.file_name
    link.target = '_blank'  // 在新标签页中打开
    link.rel = 'noopener noreferrer'  // 安全属性
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    
    ElMessage.success('下载成功')
  } catch (error) {
    console.error('下载失败:', error)
    ElMessage.error('下载失败：' + (error instanceof Error ? error.message : '未知错误'))
  } finally {
    sample.downloading = false
  }
}

// 初始化
onMounted(() => {
  fetchSamples()
})
</script>

<style scoped>
.samples-container {
  padding: 20px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.search-bar {
  margin-bottom: 20px;
}

.search-input {
  width: 300px;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.description-section,
.analysis-section {
  margin-top: 20px;
  padding: 15px;
  background-color: #f5f7fa;
  border-radius: 4px;
}

.analysis-section pre {
  white-space: pre-wrap;
  word-wrap: break-word;
  margin: 0;
  padding: 10px;
  background-color: #fff;
  border-radius: 4px;
}
</style> 