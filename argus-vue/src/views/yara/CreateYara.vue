<template>
  <div class="create-yara-container">
    <el-card class="yara-card">
      <template #header>
        <div class="card-header">
          <h2>创建Yara规则</h2>
        </div>
      </template>
      
      <el-form :model="yaraForm" :rules="rules" ref="yaraFormRef" label-width="120px">
        <el-form-item label="规则名称" prop="name">
          <el-input v-model="yaraForm.name" placeholder="请输入规则名称"></el-input>
        </el-form-item>
        
        <el-form-item label="规则描述" prop="description">
          <el-input
            v-model="yaraForm.description"
            type="textarea"
            :rows="3"
            placeholder="请输入规则描述"
          ></el-input>
        </el-form-item>
        
        <el-form-item label="规则内容" prop="content">
          <el-input
            v-model="yaraForm.content"
            type="textarea"
            :rows="10"
            placeholder="请输入Yara规则内容"
            class="yara-content"
          ></el-input>
        </el-form-item>
        
        <el-form-item>
          <el-button type="primary" @click="submitForm">创建规则</el-button>
          <el-button @click="resetForm">重置</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import type { FormInstance, FormRules } from 'element-plus'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'
import { yaraApi } from '@/api/yara'

const router = useRouter()
const yaraFormRef = ref<FormInstance>()
const yaraForm = reactive({
  name: '',
  description: '',
  content: ''
})

const rules = reactive<FormRules>({
  name: [
    { required: true, message: '请输入规则名称', trigger: 'blur' },
    { min: 3, max: 50, message: '长度在 3 到 50 个字符', trigger: 'blur' }
  ],
  description: [
    { required: true, message: '请输入规则描述', trigger: 'blur' }
  ],
  content: [
    { required: true, message: '请输入规则内容', trigger: 'blur' }
  ]
})

const submitForm = async () => {
  if (!yaraFormRef.value) return
  
  await yaraFormRef.value.validate(async (valid) => {
    if (valid) {
      try {
        await yaraApi.createRule(yaraForm)
        ElMessage.success('规则创建成功')
        router.push('/yara/list')
      } catch (error: any) {
        ElMessage.error(error.response?.data?.detail || '创建规则失败')
      }
    }
  })
}

const resetForm = () => {
  if (!yaraFormRef.value) return
  yaraFormRef.value.resetFields()
}
</script>

<style scoped>
.create-yara-container {
  padding: 20px;
  height: 100%;
  background-color: var(--el-bg-color);
}

.yara-card {
  max-width: 1000px;
  margin: 0 auto;
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

.yara-content {
  font-family: monospace;
}
</style> 