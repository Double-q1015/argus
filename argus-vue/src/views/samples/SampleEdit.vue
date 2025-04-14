<template>
  <div class="sample-edit">
    <el-card v-loading="loading">
      <template #header>
        <div class="card-header">
          <h2>{{ isEdit ? '编辑样本' : '新建样本' }}</h2>
        </div>
      </template>

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-width="120px"
        @submit.prevent="handleSubmit"
      >
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" placeholder="请输入样本名称" />
        </el-form-item>

        <el-form-item label="MIME类型" prop="mime">
          <el-select v-model="form.mime" placeholder="请选择MIME类型">
            <el-option
              v-for="item in mimeTypes"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>

        <el-form-item label="提交类型" prop="submission_type">
          <el-select v-model="form.submission_type" placeholder="请选择提交类型">
            <el-option
              v-for="item in submissionTypes"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>

        <el-form-item label="标签" prop="tags">
          <el-select
            v-model="form.tags"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="请选择或输入标签"
          >
            <el-option
              v-for="tag in commonTags"
              :key="tag"
              :label="tag"
              :value="tag"
            />
          </el-select>
        </el-form-item>

        <el-form-item label="文件" prop="file">
          <el-upload
            class="upload-demo"
            drag
            action="/api/upload"
            :auto-upload="false"
            :on-change="handleFileChange"
            :file-list="fileList"
            :limit="1"
          >
            <el-icon class="el-icon--upload"><upload-filled /></el-icon>
            <div class="el-upload__text">
              拖拽文件到此处或 <em>点击上传</em>
            </div>
          </el-upload>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="handleSubmit" :loading="submitting">
            保存
          </el-button>
          <el-button @click="handleCancel">取消</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import type { FormInstance, UploadFile } from 'element-plus'
import { UploadFilled } from '@element-plus/icons-vue'
import { useSamplesStore } from '@/store/modules/samples'

const route = useRoute()
const router = useRouter()
const samplesStore = useSamplesStore()

const formRef = ref<FormInstance>()
const loading = ref(false)
const submitting = ref(false)
const fileList = ref<UploadFile[]>([])

const isEdit = computed(() => !!route.params.id)

const form = reactive({
  name: '',
  mime: '',
  submission_type: '',
  tags: [] as string[],
  file: null as File | null
})

const rules = {
  name: [
    { required: true, message: '请输入样本名称', trigger: 'blur' }
  ],
  mime: [
    { required: true, message: '请选择MIME类型', trigger: 'change' }
  ],
  submission_type: [
    { required: true, message: '请选择提交类型', trigger: 'change' }
  ],
  file: [
    { required: !isEdit.value, message: '请上传文件', trigger: 'change' }
  ]
}

const mimeTypes = [
  { label: '可执行文件', value: 'application/x-executable' },
  { label: 'PDF文档', value: 'application/pdf' },
  { label: 'Word文档', value: 'application/msword' },
  { label: 'Excel文档', value: 'application/vnd.ms-excel' },
  { label: '图片文件', value: 'image/jpeg' },
  { label: '压缩文件', value: 'application/zip' }
]

const submissionTypes = [
  { label: '手动上传', value: 'manual' },
  { label: '自动扫描', value: 'scan' },
  { label: 'API提交', value: 'api' }
]

const commonTags = [
  '恶意软件',
  '病毒',
  '木马',
  '勒索软件',
  '可疑文件',
  '正常文件',
  '待分析'
]

const fetchSample = async () => {
  if (!isEdit.value) return
  
  const id = route.params.id as string
  loading.value = true
  try {
    await samplesStore.fetchSampleById(id)
    const sample = samplesStore.currentSample
    if (sample) {
      form.name = sample.file_name
      form.mime = sample.file_type
      form.tags = sample.tags
    }
  } catch (error) {
    ElMessage.error('获取样本信息失败')
  } finally {
    loading.value = false
  }
}

const handleFileChange = (file: UploadFile) => {
  form.file = file.raw || null
}

const handleSubmit = async () => {
  if (!formRef.value) return
  
  try {
    await formRef.value.validate()
    submitting.value = true
    
    if (isEdit.value) {
      ElMessage.warning('更新功能暂不可用')
      router.push('/samples')
    } else {
      if (form.file) {
        await samplesStore.createSample(form.file, form.tags)
        ElMessage.success('创建成功')
        router.push('/samples')
      } else {
        ElMessage.error('请上传文件')
      }
    }
  } catch (error) {
    console.error('保存失败:', error)
    ElMessage.error('保存失败')
  } finally {
    submitting.value = false
  }
}

const handleCancel = () => {
  router.back()
}

onMounted(() => {
  fetchSample()
})
</script>

<style scoped>
.sample-edit {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h2 {
  margin: 0;
}

.upload-demo {
  width: 100%;
}
</style> 