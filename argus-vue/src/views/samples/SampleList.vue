<template>
  <div class="sample-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <div class="search-bar">
            <el-input
              v-model="searchQuery"
              placeholder="搜索样本..."
              clearable
              @clear="handleSearch"
              @keyup.enter="handleSearch"
            >
              <template #prefix>
                <el-icon><Search /></el-icon>
              </template>
            </el-input>
            <el-select
              v-model="selectedTags"
              multiple
              collapse-tags
              collapse-tags-tooltip
              placeholder="选择标签"
              clearable
              @change="handleSearch"
            >
              <el-option
                v-for="tag in store.commonTags"
                :key="tag"
                :label="tag"
                :value="tag"
              />
            </el-select>
          </div>
          <el-button type="primary" @click="handleUpload">
            <el-icon><Upload /></el-icon>
            上传样本
          </el-button>
        </div>
      </template>

      <el-table
        v-loading="store.loading"
        :data="store.samples"
        style="width: 100%"
      >
        <el-table-column prop="sha256_digest" label="SHA256摘要" min-width="220">
          <template #default="{ row }">
            <router-link :to="`/samples/${row.sha256_digest}`">
              {{ row.sha256_digest }}
            </router-link>
          </template>
        </el-table-column>
        <el-table-column prop="name" label="名称" min-width="150" />
        <el-table-column prop="mime" label="MIME类型" min-width="120" />
        <el-table-column prop="size" label="大小" width="120">
          <template #default="{ row }">
            {{ formatBytes(row.size) }}
          </template>
        </el-table-column>
        <el-table-column prop="submission_type" label="提交类型" width="120" />
        <el-table-column prop="timestamp" label="时间戳" width="180">
          <template #default="{ row }">
            {{ formatDate(row.timestamp) }}
          </template>
        </el-table-column>
        <el-table-column label="标签" min-width="200">
          <template #default="{ row }">
            <el-tag
              v-for="tag in row.tags"
              :key="tag"
              class="mx-1"
              size="small"
            >
              {{ tag }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button-group>
              <el-button
                type="primary"
                link
                @click="handleView(row.sha256_digest)"
              >
                查看
              </el-button>
              <el-button
                type="primary"
                link
                @click="handleEdit(row.sha256_digest)"
              >
                编辑
              </el-button>
              <el-popconfirm
                title="确定要删除这个样本吗？"
                @confirm="handleDelete(row.sha256_digest)"
              >
                <template #reference>
                  <el-button type="danger" link>删除</el-button>
                </template>
              </el-popconfirm>
            </el-button-group>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :total="store.total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>

    <!-- 上传样本对话框 -->
    <el-dialog
      v-model="uploadDialogVisible"
      title="上传样本"
      width="500px"
    >
      <el-form
        ref="uploadFormRef"
        :model="uploadForm"
        :rules="uploadRules"
        label-width="100px"
      >
        <el-form-item label="样本文件" prop="file">
          <el-upload
            ref="uploadRef"
            class="upload-demo"
            drag
            action="#"
            :auto-upload="false"
            :limit="1"
            :on-change="handleFileChange"
          >
            <el-icon class="el-icon--upload"><upload-filled /></el-icon>
            <div class="el-upload__text">
              拖拽文件到此处或 <em>点击上传</em>
            </div>
          </el-upload>
        </el-form-item>
        <el-form-item label="样本名称" prop="name">
          <el-input v-model="uploadForm.name" placeholder="请输入样本名称" />
        </el-form-item>
        <el-form-item label="提交类型" prop="submission_type">
          <el-select
            v-model="uploadForm.submission_type"
            placeholder="请选择提交类型"
          >
            <el-option label="手动提交" value="manual" />
            <el-option label="自动提交" value="automatic" />
            <el-option label="API提交" value="api" />
          </el-select>
        </el-form-item>
        <el-form-item label="标签" prop="tags">
          <el-select
            v-model="uploadForm.tags"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="请选择或输入标签"
          >
            <el-option
              v-for="tag in store.commonTags"
              :key="tag"
              :label="tag"
              :value="tag"
            />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="uploadDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="submitUpload">
            确认上传
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { Search, Upload, UploadFilled } from '@element-plus/icons-vue'
import { useSamplesStore } from '@/stores/samples'
import { formatBytes } from '@/utils/format'
import type { FormInstance, UploadInstance } from 'element-plus'

const router = useRouter()
const store = useSamplesStore()

// 搜索和筛选
const searchQuery = ref('')
const selectedTags = ref<string[]>([])
const currentPage = ref(1)
const pageSize = ref(10)

// 上传对话框
const uploadDialogVisible = ref(false)
const uploadFormRef = ref<FormInstance>()
const uploadRef = ref<UploadInstance>()
const uploadForm = ref({
  file: null as File | null,
  name: '',
  submission_type: '',
  tags: [] as string[]
})

const uploadRules = {
  file: [{ required: true, message: '请选择要上传的文件', trigger: 'change' }],
  submission_type: [{ required: true, message: '请选择提交类型', trigger: 'change' }]
}

const formatDate = (timestamp: string) => {
  return new Date(timestamp).toLocaleString()
}

const handleSearch = () => {
  store.fetchSamples({
    search: searchQuery.value,
    limit: pageSize.value,
  })
}

const handleSizeChange = (val: number) => {
  pageSize.value = val
  handleSearch()
}

const handleCurrentChange = (val: number) => {
  currentPage.value = val
  handleSearch()
}

const handleUpload = () => {
  uploadDialogVisible.value = true
}

const handleFileChange = (file: any) => {
  uploadForm.value.file = file.raw
}

const submitUpload = async () => {
  if (!uploadFormRef.value) return
  
  await uploadFormRef.value.validate(async (valid) => {
    if (valid && uploadForm.value.file) {
      try {
        const sample = await store.uploadSample(
          uploadForm.value.file,
          uploadForm.value.tags,
          uploadForm.value.name
        )
        
        if (sample) {
          uploadDialogVisible.value = false
          handleSearch()
          uploadRef.value?.clearFiles()
          uploadForm.value = {
            file: null,
            name: '',
            submission_type: '',
            tags: []
          }
        }
      } catch (error) {
        console.error('上传样本失败:', error)
      }
    }
  })
}

const handleView = (sha256: string) => {
  router.push(`/samples/${sha256}`)
}

const handleEdit = (sha256: string) => {
  router.push(`/samples/${sha256}/edit`)
}

const handleDelete = async (sha256: string) => {
  const success = await store.deleteSample(sha256)
  if (success) {
    handleSearch()
  }
}

onMounted(async () => {
  await Promise.all([
    store.fetchSamples(),
    store.fetchCommonTags()
  ])
})
</script>

<style scoped>
.sample-list {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.search-bar {
  display: flex;
  gap: 10px;
  flex: 1;
  margin-right: 20px;
}

.search-bar .el-input {
  width: 300px;
}

.search-bar .el-select {
  width: 200px;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.mx-1 {
  margin: 0 4px;
}

:deep(.el-upload-dragger) {
  width: 100%;
}

:deep(.el-upload) {
  width: 100%;
}
</style> 
<template>
  <div class="sample-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <div class="search-bar">
            <el-input
              v-model="searchQuery"
              placeholder="搜索样本..."
              clearable
              @clear="handleSearch"
              @keyup.enter="handleSearch"
            >
              <template #prefix>
                <el-icon><Search /></el-icon>
              </template>
            </el-input>
            <el-select
              v-model="selectedTags"
              multiple
              collapse-tags
              collapse-tags-tooltip
              placeholder="选择标签"
              clearable
              @change="handleSearch"
            >
              <el-option
                v-for="tag in store.commonTags"
                :key="tag"
                :label="tag"
                :value="tag"
              />
            </el-select>
          </div>
          <el-button type="primary" @click="handleUpload">
            <el-icon><Upload /></el-icon>
            上传样本
          </el-button>
        </div>
      </template>

      <el-table
        v-loading="store.loading"
        :data="store.samples"
        style="width: 100%"
      >
        <el-table-column prop="sha256_digest" label="SHA256摘要" min-width="220">
          <template #default="{ row }">
            <router-link :to="`/samples/${row.sha256_digest}`">
              {{ row.sha256_digest }}
            </router-link>
          </template>
        </el-table-column>
        <el-table-column prop="name" label="名称" min-width="150" />
        <el-table-column prop="mime" label="MIME类型" min-width="120" />
        <el-table-column prop="size" label="大小" width="120">
          <template #default="{ row }">
            {{ formatBytes(row.size) }}
          </template>
        </el-table-column>
        <el-table-column prop="submission_type" label="提交类型" width="120" />
        <el-table-column prop="timestamp" label="时间戳" width="180">
          <template #default="{ row }">
            {{ formatDate(row.timestamp) }}
          </template>
        </el-table-column>
        <el-table-column label="标签" min-width="200">
          <template #default="{ row }">
            <el-tag
              v-for="tag in row.tags"
              :key="tag"
              class="mx-1"
              size="small"
            >
              {{ tag }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button-group>
              <el-button
                type="primary"
                link
                @click="handleView(row.sha256_digest)"
              >
                查看
              </el-button>
              <el-button
                type="primary"
                link
                @click="handleEdit(row.sha256_digest)"
              >
                编辑
              </el-button>
              <el-popconfirm
                title="确定要删除这个样本吗？"
                @confirm="handleDelete(row.sha256_digest)"
              >
                <template #reference>
                  <el-button type="danger" link>删除</el-button>
                </template>
              </el-popconfirm>
            </el-button-group>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :total="store.total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>

    <!-- 上传样本对话框 -->
    <el-dialog
      v-model="uploadDialogVisible"
      title="上传样本"
      width="500px"
    >
      <el-form
        ref="uploadFormRef"
        :model="uploadForm"
        :rules="uploadRules"
        label-width="100px"
      >
        <el-form-item label="样本文件" prop="file">
          <el-upload
            ref="uploadRef"
            class="upload-demo"
            drag
            action="#"
            :auto-upload="false"
            :limit="1"
            :on-change="handleFileChange"
          >
            <el-icon class="el-icon--upload"><upload-filled /></el-icon>
            <div class="el-upload__text">
              拖拽文件到此处或 <em>点击上传</em>
            </div>
          </el-upload>
        </el-form-item>
        <el-form-item label="样本名称" prop="name">
          <el-input v-model="uploadForm.name" placeholder="请输入样本名称" />
        </el-form-item>
        <el-form-item label="提交类型" prop="submission_type">
          <el-select
            v-model="uploadForm.submission_type"
            placeholder="请选择提交类型"
          >
            <el-option label="手动提交" value="manual" />
            <el-option label="自动提交" value="automatic" />
            <el-option label="API提交" value="api" />
          </el-select>
        </el-form-item>
        <el-form-item label="标签" prop="tags">
          <el-select
            v-model="uploadForm.tags"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="请选择或输入标签"
          >
            <el-option
              v-for="tag in store.commonTags"
              :key="tag"
              :label="tag"
              :value="tag"
            />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="uploadDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="submitUpload">
            确认上传
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { Search, Upload, UploadFilled } from '@element-plus/icons-vue'
import { useSamplesStore } from '@/stores/samples'
import { formatBytes } from '@/utils/format'
import type { FormInstance, UploadInstance } from 'element-plus'

const router = useRouter()
const store = useSamplesStore()

// 搜索和筛选
const searchQuery = ref('')
const selectedTags = ref<string[]>([])
const currentPage = ref(1)
const pageSize = ref(10)

// 上传对话框
const uploadDialogVisible = ref(false)
const uploadFormRef = ref<FormInstance>()
const uploadRef = ref<UploadInstance>()
const uploadForm = ref({
  file: null as File | null,
  name: '',
  submission_type: '',
  tags: [] as string[]
})

const uploadRules = {
  file: [{ required: true, message: '请选择要上传的文件', trigger: 'change' }],
  submission_type: [{ required: true, message: '请选择提交类型', trigger: 'change' }]
}

const formatDate = (timestamp: string) => {
  return new Date(timestamp).toLocaleString()
}

const handleSearch = () => {
  store.fetchSamples({
    search: searchQuery.value,
    tags: selectedTags.value,
    limit: pageSize.value,
    order: -1,
    sort: 'timestamp'
  })
}

const handleSizeChange = (val: number) => {
  pageSize.value = val
  handleSearch()
}

const handleCurrentChange = (val: number) => {
  currentPage.value = val
  handleSearch()
}

const handleUpload = () => {
  uploadDialogVisible.value = true
}

const handleFileChange = (file: any) => {
  uploadForm.value.file = file.raw
}

const submitUpload = async () => {
  if (!uploadFormRef.value) return
  
  await uploadFormRef.value.validate(async (valid) => {
    if (valid && uploadForm.value.file) {
      try {
        const sample = await store.uploadSample({
          file: uploadForm.value.file,
          name: uploadForm.value.name,
          submission_type: uploadForm.value.submission_type,
          tags: uploadForm.value.tags
        })
        
        if (sample) {
          uploadDialogVisible.value = false
          handleSearch()
          uploadRef.value?.clearFiles()
          uploadForm.value = {
            file: null,
            name: '',
            submission_type: '',
            tags: []
          }
        }
      } catch (error) {
        console.error('上传样本失败:', error)
      }
    }
  })
}

const handleView = (sha256: string) => {
  router.push(`/samples/${sha256}`)
}

const handleEdit = (sha256: string) => {
  router.push(`/samples/${sha256}/edit`)
}

const handleDelete = async (sha256: string) => {
  const success = await store.deleteSample(sha256)
  if (success) {
    handleSearch()
  }
}

onMounted(async () => {
  await Promise.all([
    store.fetchSamples(),
    store.fetchCommonTags()
  ])
})
</script>

<style scoped>
.sample-list {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.search-bar {
  display: flex;
  gap: 10px;
  flex: 1;
  margin-right: 20px;
}

.search-bar .el-input {
  width: 300px;
}

.search-bar .el-select {
  width: 200px;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.mx-1 {
  margin: 0 4px;
}

:deep(.el-upload-dragger) {
  width: 100%;
}

:deep(.el-upload) {
  width: 100%;
}
</style> 
<template>
  <div class="sample-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <div class="search-bar">
            <el-input
              v-model="searchQuery"
              placeholder="搜索样本..."
              clearable
              @clear="handleSearch"
              @keyup.enter="handleSearch"
            >
              <template #prefix>
                <el-icon><Search /></el-icon>
              </template>
            </el-input>
            <el-select
              v-model="selectedTags"
              multiple
              collapse-tags
              collapse-tags-tooltip
              placeholder="选择标签"
              clearable
              @change="handleSearch"
            >
              <el-option
                v-for="tag in store.commonTags"
                :key="tag"
                :label="tag"
                :value="tag"
              />
            </el-select>
          </div>
          <el-button type="primary" @click="handleUpload">
            <el-icon><Upload /></el-icon>
            上传样本
          </el-button>
        </div>
      </template>

      <el-table
        v-loading="store.loading"
        :data="store.samples"
        style="width: 100%"
      >
        <el-table-column prop="sha256_digest" label="SHA256摘要" min-width="220">
          <template #default="{ row }">
            <router-link :to="`/samples/${row.sha256_digest}`">
              {{ row.sha256_digest }}
            </router-link>
          </template>
        </el-table-column>
        <el-table-column prop="name" label="名称" min-width="150" />
        <el-table-column prop="mime" label="MIME类型" min-width="120" />
        <el-table-column prop="size" label="大小" width="120">
          <template #default="{ row }">
            {{ formatBytes(row.size) }}
          </template>
        </el-table-column>
        <el-table-column prop="submission_type" label="提交类型" width="120" />
        <el-table-column prop="timestamp" label="时间戳" width="180">
          <template #default="{ row }">
            {{ formatDate(row.timestamp) }}
          </template>
        </el-table-column>
        <el-table-column label="标签" min-width="200">
          <template #default="{ row }">
            <el-tag
              v-for="tag in row.tags"
              :key="tag"
              class="mx-1"
              size="small"
            >
              {{ tag }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button-group>
              <el-button
                type="primary"
                link
                @click="handleView(row.sha256_digest)"
              >
                查看
              </el-button>
              <el-button
                type="primary"
                link
                @click="handleEdit(row.sha256_digest)"
              >
                编辑
              </el-button>
              <el-popconfirm
                title="确定要删除这个样本吗？"
                @confirm="handleDelete(row.sha256_digest)"
              >
                <template #reference>
                  <el-button type="danger" link>删除</el-button>
                </template>
              </el-popconfirm>
            </el-button-group>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :total="store.total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>

    <!-- 上传样本对话框 -->
    <el-dialog
      v-model="uploadDialogVisible"
      title="上传样本"
      width="500px"
    >
      <el-form
        ref="uploadFormRef"
        :model="uploadForm"
        :rules="uploadRules"
        label-width="100px"
      >
        <el-form-item label="样本文件" prop="file">
          <el-upload
            ref="uploadRef"
            class="upload-demo"
            drag
            action="#"
            :auto-upload="false"
            :limit="1"
            :on-change="handleFileChange"
          >
            <el-icon class="el-icon--upload"><upload-filled /></el-icon>
            <div class="el-upload__text">
              拖拽文件到此处或 <em>点击上传</em>
            </div>
          </el-upload>
        </el-form-item>
        <el-form-item label="样本名称" prop="name">
          <el-input v-model="uploadForm.name" placeholder="请输入样本名称" />
        </el-form-item>
        <el-form-item label="提交类型" prop="submission_type">
          <el-select
            v-model="uploadForm.submission_type"
            placeholder="请选择提交类型"
          >
            <el-option label="手动提交" value="manual" />
            <el-option label="自动提交" value="automatic" />
            <el-option label="API提交" value="api" />
          </el-select>
        </el-form-item>
        <el-form-item label="标签" prop="tags">
          <el-select
            v-model="uploadForm.tags"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="请选择或输入标签"
          >
            <el-option
              v-for="tag in store.commonTags"
              :key="tag"
              :label="tag"
              :value="tag"
            />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="uploadDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="submitUpload">
            确认上传
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { Search, Upload, UploadFilled } from '@element-plus/icons-vue'
import { useSamplesStore } from '@/stores/samples'
import { formatBytes } from '@/utils/format'
import type { FormInstance, UploadInstance } from 'element-plus'

const router = useRouter()
const store = useSamplesStore()

// 搜索和筛选
const searchQuery = ref('')
const selectedTags = ref<string[]>([])
const currentPage = ref(1)
const pageSize = ref(10)

// 上传对话框
const uploadDialogVisible = ref(false)
const uploadFormRef = ref<FormInstance>()
const uploadRef = ref<UploadInstance>()
const uploadForm = ref({
  file: null as File | null,
  name: '',
  submission_type: '',
  tags: [] as string[]
})

const uploadRules = {
  file: [{ required: true, message: '请选择要上传的文件', trigger: 'change' }],
  submission_type: [{ required: true, message: '请选择提交类型', trigger: 'change' }]
}

const formatDate = (timestamp: string) => {
  return new Date(timestamp).toLocaleString()
}

const handleSearch = () => {
  store.fetchSamples({
    search: searchQuery.value,
    tags: selectedTags.value,
    limit: pageSize.value,
    order: -1,
    sort: 'timestamp'
  })
}

const handleSizeChange = (val: number) => {
  pageSize.value = val
  handleSearch()
}

const handleCurrentChange = (val: number) => {
  currentPage.value = val
  handleSearch()
}

const handleUpload = () => {
  uploadDialogVisible.value = true
}

const handleFileChange = (file: any) => {
  uploadForm.value.file = file.raw
}

const submitUpload = async () => {
  if (!uploadFormRef.value) return
  
  await uploadFormRef.value.validate(async (valid) => {
    if (valid && uploadForm.value.file) {
      try {
        const sample = await store.uploadSample({
          file: uploadForm.value.file,
          name: uploadForm.value.name,
          submission_type: uploadForm.value.submission_type,
          tags: uploadForm.value.tags
        })
        
        if (sample) {
          uploadDialogVisible.value = false
          handleSearch()
          uploadRef.value?.clearFiles()
          uploadForm.value = {
            file: null,
            name: '',
            submission_type: '',
            tags: []
          }
        }
      } catch (error) {
        console.error('上传样本失败:', error)
      }
    }
  })
}

const handleView = (sha256: string) => {
  router.push(`/samples/${sha256}`)
}

const handleEdit = (sha256: string) => {
  router.push(`/samples/${sha256}/edit`)
}

const handleDelete = async (sha256: string) => {
  const success = await store.deleteSample(sha256)
  if (success) {
    handleSearch()
  }
}

onMounted(async () => {
  await Promise.all([
    store.fetchSamples(),
    store.fetchCommonTags()
  ])
})
</script>

<style scoped>
.sample-list {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.search-bar {
  display: flex;
  gap: 10px;
  flex: 1;
  margin-right: 20px;
}

.search-bar .el-input {
  width: 300px;
}

.search-bar .el-select {
  width: 200px;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.mx-1 {
  margin: 0 4px;
}

:deep(.el-upload-dragger) {
  width: 100%;
}

:deep(.el-upload) {
  width: 100%;
}
</style> 