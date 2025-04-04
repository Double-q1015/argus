<template>
  <div class="scale-edit">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>{{ isEdit ? '编辑规模分析' : '创建规模分析' }}</span>
        </div>
      </template>

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
            rows="10"
            placeholder="请输入JSON格式的参数"
            :class="{ 'is-invalid': !isValidJson }"
          />
          <div v-if="!isValidJson" class="error-message">
            请输入有效的JSON格式
          </div>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="handleSubmit">保存</el-button>
          <el-button @click="handleCancel">取消</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScalesStore } from '@/stores/scales'
import type { FormInstance } from 'element-plus'
import type { Scale } from '@/api/scales'

const route = useRoute()
const router = useRouter()
const store = useScalesStore()
const formRef = ref<FormInstance>()

const isEdit = computed(() => !!route.params.id)

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
      isValidJson.value = true
    } catch (error) {
      isValidJson.value = false
    }
  }
})

const isValidJson = ref(true)

const rules = {
  name: [
    { required: true, message: '请输入名称', trigger: 'blur' },
    { min: 2, max: 50, message: '长度在 2 到 50 个字符', trigger: 'blur' }
  ],
  type: [
    { required: true, message: '请选择类型', trigger: 'change' }
  ]
}

const initForm = async () => {
  if (isEdit.value) {
    await store.fetchScaleDetail(route.params.id as string)
    if (store.currentScale) {
      form.value = {
        name: store.currentScale.name,
        description: store.currentScale.description,
        type: store.currentScale.type,
        parameters: store.currentScale.parameters
      }
    }
  }
}

const handleSubmit = async () => {
  if (!formRef.value || !isValidJson.value) return

  await formRef.value.validate(async (valid) => {
    if (valid) {
      try {
        if (isEdit.value) {
          const success = await store.updateScale(route.params.id as string, form.value)
          if (success) {
            router.push(`/scales/${route.params.id}`)
          }
        } else {
          const scale = await store.createScale(form.value)
          if (scale) {
            router.push(`/scales/${scale.id}`)
          }
        }
      } catch (error) {
        console.error('提交失败:', error)
      }
    }
  })
}

const handleCancel = () => {
  router.back()
}

onMounted(() => {
  initForm()
})
</script>

<style scoped>
.scale-edit {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.is-invalid {
  border-color: var(--el-color-danger);
}

.error-message {
  color: var(--el-color-danger);
  font-size: 12px;
  margin-top: 4px;
}

:deep(.el-form-item) {
  margin-bottom: 22px;
}

:deep(.el-select) {
  width: 100%;
}
</style> 