<template>
  <div class="login-container">
    <el-card class="login-card">
      <template #header>
        <h2>登录</h2>
      </template>
      
      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        :hide-required-asterisk="true"
        @submit.prevent="handleSubmit"
      >
        <el-form-item prop="username">
          <template #label><span class="required-label">用户名</span></template>
          <el-input v-model="form.username" />
        </el-form-item>
        
        <el-form-item prop="password">
          <template #label><span class="required-label">密码</span></template>
          <el-input
            v-model="form.password"
            type="password"
            show-password
          />
        </el-form-item>

        <el-form-item prop="captcha">
          <template #label><span class="required-label">验证码</span></template>
          <div class="captcha-container">
            <el-input 
              v-model="form.captcha" 
              placeholder="请输入验证码"
              style="width: 200px;"
            />
            <div class="captcha-img-container">
              <img 
                :src="captchaUrl" 
                alt="验证码" 
                class="captcha-img"
                @click="refreshCaptcha"
              />
            </div>
          </div>
        </el-form-item>
        
        <el-form-item>
          <el-button type="primary" native-type="submit" :loading="loading">
            登录
          </el-button>
          <el-button @click="$router.push('/register')">
            注册
          </el-button>
        </el-form-item>
      </el-form>
      
      <div v-if="error" class="error-message">
        {{ error }}
      </div>
      
      <div class="password-requirements">
        <h4>密码要求：</h4>
        <ul>
          <li>至少8个字符</li>
          <li>至少包含一个大写字母</li>
          <li>至少包含一个小写字母</li>
          <li>至少包含一个数字</li>
          <li>至少包含一个特殊字符</li>
        </ul>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import type { FormInstance } from 'element-plus'
import { login } from '@/api/auth'

const router = useRouter()
const formRef = ref<FormInstance>()
const loading = ref(false)
const error = ref('')
const captchaUrl = ref('')

const form = reactive({
  username: '',
  password: '',
  captcha: '',
  client_id: ''  // 用于存储session_id
})

const rules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { min: 3, max: 20, message: '用户名长度应在3-20个字符之间', trigger: 'blur' }
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 8, message: '密码长度至少为8个字符', trigger: 'blur' }
  ],
  captcha: [
    { required: true, message: '请输入验证码', trigger: 'blur' }
  ]
}

// 刷新验证码
const refreshCaptcha = () => {
  // 生成随机的session_id
  form.client_id = Math.random().toString(36).substring(2)
  // 添加时间戳防止缓存
  captchaUrl.value = `/api/v1/auth/captcha?client_id=${form.client_id}&t=${new Date().getTime()}`
}

const handleSubmit = async () => {
  if (!formRef.value) return
  
  try {
    await formRef.value.validate()
    loading.value = true
    error.value = ''
    
    const response = await login(form)
    localStorage.setItem('access_token', response.access_token)
    localStorage.setItem('username', form.username)
    ElMessage.success('登录成功')
    router.push('/')
  } catch (err: any) {
    if (err.response?.data?.detail) {
      error.value = err.response.data.detail
    } else {
      error.value = '登录失败，请检查用户名和密码'
    }
    // 登录失败时刷新验证码
    refreshCaptcha()
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  refreshCaptcha()
})
</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background-color: #f5f7fa;
}

.login-card {
  width: 100%;
  max-width: 400px;
}

.error-message {
  color: #f56c6c;
  margin-top: 10px;
  text-align: center;
}

.password-requirements {
  margin-top: 20px;
  padding: 10px;
  background-color: #f5f7fa;
  border-radius: 4px;
}

.password-requirements h4 {
  margin: 0 0 10px 0;
  color: #606266;
}

.password-requirements ul {
  margin: 0;
  padding-left: 20px;
  color: #909399;
}

.password-requirements li {
  margin: 5px 0;
}

.captcha-container {
  display: flex;
  align-items: center;
  gap: 10px;
}

.captcha-img-container {
  width: 80px;
  height: 30px;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  overflow: hidden;
  cursor: pointer;
}

.captcha-img {
  width: 100%;
  height: 100%;
  object-fit: contain;
}

:deep(.el-form-item) {
  margin-bottom: 20px;
}

:deep(.el-form-item__content) {
  display: flex;
  align-items: center;
}

:deep(.el-input) {
  width: 100%;
}

:deep(.el-form-item__label) {
  width: 70px;
  justify-content: flex-start;
  padding: 0;
}

.required-label::before {
  content: '*';
  color: #f56c6c;
  margin-right: 4px;
}

:deep(.el-input__wrapper) {
  box-shadow: none;
  border: 1px solid #dcdfe6;
}
</style> 