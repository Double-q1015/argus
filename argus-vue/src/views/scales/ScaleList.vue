<template>
  <div class="scale-list">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>规模分析</span>
          <el-button type="primary" @click="handleCreate">
            <el-icon><Plus /></el-icon>
            创建规模分析
          </el-button>
        </div>
      </template>

      <el-table
        v-loading="store.loading"
        :data="store.scales"
        style="width: 100%"
      >
        <el-table-column prop="name" label="名称" min-width="150">
          <template #default="{ row }">
            <router-link :to="`/scales/${row.id}`">
              {{ row.name }}
            </router-link>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
        <el-table-column prop="type" label="类型" width="120">
          <template #default="{ row }">
            <el-tag :type="getTypeTagType(row.type)">
              {{ formatType(row.type) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="120">
          <template #default="{ row }">
            <el-tag :type="getStatusTagType(row.status)">
              {{ formatStatus(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column prop="updated_at" label="更新时间" width="180">
          <template #default="{ row }">
            {{ formatDate(row.updated_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="250" fixed="right">
          <template #default="{ row }">
            <el-button-group>
              <el-button
                type="primary"
                link
                @click="handleView(row.id)"
              >
                查看
              </el-button>
              <el-button
                type="primary"
                link
                @click="handleEdit(row.id)"
              >
                编辑
              </el-button>
              <el-button
                v-if="row.status === 'inactive'"
                type="success"
                link
                @click="handleStart(row.id)"
              >
                启动
              </el-button>
              <el-button
                v-else
                type="warning"
                link
                @click="handleStop(row.id)"
              >
                停止
              </el-button>
              <el-popconfirm
                title="确定要删除这个规模分析吗？"
                @confirm="handleDelete(row.id)"
              >
                <template #reference>
                  <el-button type="danger" link>删除</el-button>
                </template>
              </el-popconfirm>
            </el-button-group>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 创建/编辑对话框 -->
    <el-dialog
      v-model="dialogVisible"
      :title="isEdit ? '编辑规模分析' : '创建规模分析'"
      width="600px"
    >
      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-width="100px"
      >
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" placeholder="请输入名称" />
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input
            v-model="form.description"
            type="textarea"
            rows="3"
            placeholder="请输入描述"
          />
        </el-form-item>
        <el-form-item label="类型" prop="type">
          <el-select v-model="form.type" placeholder="请选择类型">
            <el-option label="静态分析" value="static" />
            <el-option label="动态分析" value="dynamic" />
            <el-option label="混合分析" value="hybrid" />
          </el-select>
        </el-form-item>
        <el-form-item label="参数" prop="parameters">
          <el-input
            v-model="parametersStr"
            type="textarea"
            rows="5"
            placeholder="请输入JSON格式的参数"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="dialogVisible = false">取消</el-button>
          <el-button type="primary" @click="handleSubmit">
            确认
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { Plus } from '@element-plus/icons-vue'
import { useScalesStore } from '@/stores/scales'
import type { FormInstance } from 'element-plus'
import type { Scale } from '@/api/scales'

const router = useRouter()
const store = useScalesStore()

// 表单相关
const dialogVisible = ref(false)
const isEdit = ref(false)
const formRef = ref<FormInstance>()
const form = ref({
  name: '',
  description: '',
  type: '' as Scale['type'],
  parameters: {}
})

const parametersStr = computed({
  get: () => JSON.stringify(form.value.parameters, null, 2),
  set: (val) => {
    try {
      form.value.parameters = JSON.parse(val)
    } catch (error) {
      console.error('JSON解析失败:', error)
    }
  }
})

const rules = {
  name: [{ required: true, message: '请输入名称', trigger: 'blur' }],
  type: [{ required: true, message: '请选择类型', trigger: 'change' }]
}

// 格式化函数
const formatDate = (timestamp: string) => {
  return new Date(timestamp).toLocaleString()
}

const formatType = (type: Scale['type']) => {
  const typeMap = {
    static: '静态分析',
    dynamic: '动态分析',
    hybrid: '混合分析'
  }
  return typeMap[type] || type
}

const formatStatus = (status: Scale['status']) => {
  return status === 'active' ? '运行中' : '已停止'
}

const getTypeTagType = (type: Scale['type']) => {
  const typeMap = {
    static: 'info',
    dynamic: 'warning',
    hybrid: 'success'
  }
  return typeMap[type] || 'info'
}

const getStatusTagType = (status: Scale['status']) => {
  return status === 'active' ? 'success' : 'info'
}

// 事件处理函数
const resetForm = () => {
  form.value = {
    name: '',
    description: '',
    type: '' as Scale['type'],
    parameters: {}
  }
}

const handleCreate = () => {
  isEdit.value = false
  resetForm()
  dialogVisible.value = true
}

const handleEdit = async (id: string) => {
  isEdit.value = true
  await store.fetchScaleDetail(id)
  if (store.currentScale) {
    form.value = {
      name: store.currentScale.name,
      description: store.currentScale.description,
      type: store.currentScale.type,
      parameters: store.currentScale.parameters
    }
  }
  dialogVisible.value = true
}

const handleView = (id: string) => {
  router.push(`/scales/${id}`)
}

const handleSubmit = async () => {
  if (!formRef.value) return
  
  await formRef.value.validate(async (valid) => {
    if (valid) {
      try {
        if (isEdit.value && store.currentScale) {
          const success = await store.updateScale(store.currentScale.id, form.value)
          if (success) {
            dialogVisible.value = false
          }
        } else {
          const success = await store.createScale(form.value)
          if (success) {
            dialogVisible.value = false
          }
        }
      } catch (error) {
        console.error('提交失败:', error)
      }
    }
  })
}

const handleStart = async (id: string) => {
  await store.startScale(id)
}

const handleStop = async (id: string) => {
  await store.stopScale(id)
}

const handleDelete = async (id: string) => {
  const success = await store.deleteScale(id)
  if (success) {
    await store.fetchScales()
  }
}

// 组件挂载时获取数据
onMounted(() => {
  store.fetchScales()
})
</script>

<style scoped>
.scale-list {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

:deep(.el-table) {
  margin-top: 20px;
}

.dialog-footer {
  margin-top: 20px;
}
</style> 