<template>
  <div class="sample-list">
    <el-table :data="samples" style="width: 100%">
      <el-table-column prop="file_name" label="文件名" />
      <el-table-column prop="sha256_digest" label="SHA256" />
      <el-table-column prop="file_type" label="文件类型" />
      <el-table-column prop="file_size" label="文件大小">
        <template #default="{ row }">
          {{ formatBytes(row.file_size) }}
        </template>
      </el-table-column>
      <el-table-column prop="upload_time" label="上传时间">
        <template #default="{ row }">
          {{ formatDate(row.upload_time) }}
        </template>
      </el-table-column>
      <el-table-column label="操作" width="300">
        <template #default="{ row }">
          <el-button type="primary" size="small" @click="handleView(row)">详情</el-button>
          <el-button type="success" size="small" @click="showDownloadDialog(row)">下载</el-button>
          <el-button type="danger" size="small" @click="handleDelete(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 下载对话框 -->
    <el-dialog
      v-model="downloadDialogVisible"
      title="下载样本"
      width="30%"
    >
      <el-form :model="downloadForm" label-width="100px">
        <el-form-item label="加密下载">
          <el-switch v-model="downloadForm.encrypted" />
        </el-form-item>
        <el-form-item label="密码" v-if="downloadForm.encrypted">
          <el-input
            v-model="downloadForm.password"
            type="password"
            placeholder="请输入密码"
            show-password
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="downloadDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="confirmDownload">
            确认下载
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useUserStore } from '@/stores/user'
import { API_BASE_URL } from '@/config'
import { useRouter } from 'vue-router'
import { formatBytes, formatDate } from '@/utils/format'

const userStore = useUserStore()
const token = ref(userStore.token)
const router = useRouter()

// 样本列表数据
const samples = ref([])

// 下载相关的状态
const downloadDialogVisible = ref(false)
const downloadForm = ref({
  encrypted: false,
  password: '',
  sample: null
})

// 获取样本列表
const fetchSamples = async () => {
  try {
    console.log('开始获取样本列表...')
    const response = await fetch(`${API_BASE_URL}/samples`, {
      headers: {
        'Authorization': `Bearer ${token.value}`
      }
    })
    if (!response.ok) {
      throw new Error('获取样本列表失败')
    }
    const data = await response.json()
    console.log('获取到的样本列表:', data)
    samples.value = data
  } catch (error) {
    console.error('获取样本列表失败:', error)
    ElMessage.error('获取样本列表失败')
  }
}

// 显示下载对话框
const showDownloadDialog = (sample) => {
  console.log('显示下载对话框，样本信息:', sample)
  if (!sample) {
    console.error('样本信息为空')
    return
  }
  downloadForm.value = {
    encrypted: false,
    password: '',
    sample: sample
  }
  downloadDialogVisible.value = true
}

// 处理查看详情
const handleView = (row) => {
  router.push(`/samples/${row.sha256_digest}`)
}

// 处理删除
const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm('确定要删除这个样本吗？', '警告', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })
    const response = await fetch(`${API_BASE_URL}/samples/${row.sha256_digest}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token.value}`
      }
    })
    if (!response.ok) {
      throw new Error('删除失败')
    }
    ElMessage.success('删除成功')
    await fetchSamples()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('删除失败:', error)
      ElMessage.error('删除失败')
    }
  }
}

// 处理确认下载
const confirmDownload = async () => {
  if (!downloadForm.value.sample) {
    console.error('没有选择样本')
    return
  }

  try {
    console.log('开始下载，表单信息:', downloadForm.value)
    const url = `${API_BASE_URL}/samples/${downloadForm.value.sample.sha256_digest}/download${
      downloadForm.value.encrypted ? `?password=${encodeURIComponent(downloadForm.value.password || 'infected')}` : ''
    }`
    console.log('请求URL:', url)

    const response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${token.value}`
      }
    })

    if (!response.ok) {
      const errorText = await response.text()
      console.error('下载失败，响应:', errorText)
      throw new Error('下载失败')
    }

    const data = await response.json()
    console.log('下载响应:', data)
    
    if (!data.download_url) {
      throw new Error('下载URL不存在')
    }

    // 使用a标签下载文件，添加target="_blank"在新窗口打开
    const link = document.createElement('a')
    link.href = data.download_url
    link.target = '_blank'
    link.rel = 'noopener noreferrer'
    link.download = downloadForm.value.encrypted 
      ? `${downloadForm.value.sample.file_name}.zip`
      : downloadForm.value.sample.file_name
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)

    ElMessage.success('下载成功')
    downloadDialogVisible.value = false
  } catch (error) {
    console.error('下载失败:', error)
    ElMessage.error('下载失败')
  }
}

// 组件挂载时获取样本列表
onMounted(() => {
  console.log('组件挂载，开始初始化...')
  console.log('API_BASE_URL:', API_BASE_URL)
  console.log('token:', token.value)
  fetchSamples()
})
</script> 