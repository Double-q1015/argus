<template>
  <div class="login-container">
    <div class="login-background">
      <div class="login-background-overlay"></div>
    </div>
    
    <el-card class="login-card">
      <div class="login-header">
        <img src="@/assets/logo.png" alt="Logo" class="login-logo" />
        <h2>{{ $t('login.title') }}</h2>
        <p class="login-subtitle">{{ $t('login.subtitle') }}</p>
      </div>
      
      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        :hide-required-asterisk="true"
        @submit.prevent="handleSubmit"
        class="login-form"
      >
        <el-form-item prop="username">
          <el-input 
            v-model="form.username" 
            :placeholder="$t('login.username')"
            :prefix-icon="User"
          />
        </el-form-item>
        
        <el-form-item prop="password">
          <el-input
            v-model="form.password"
            type="password"
            :placeholder="$t('login.password')"
            :prefix-icon="Lock"
            show-password
          />
        </el-form-item>

        <el-form-item prop="captcha">
          <div class="captcha-container">
            <el-input 
              v-model="form.captcha" 
              :placeholder="$t('login.captcha')"
              :prefix-icon="Key"
            />
            <div class="captcha-img-container">
              <img 
                :src="captchaUrl" 
                :alt="$t('login.captcha')" 
                class="captcha-img"
                @click="refreshCaptcha"
              />
            </div>
          </div>
        </el-form-item>
        
        <el-form-item>
          <el-button 
            type="primary" 
            native-type="submit" 
            :loading="loading"
            class="login-button"
          >
            {{ $t('login.submit') }}
          </el-button>
          <el-button 
            @click="$router.push('/register')"
            class="register-button"
          >
            {{ $t('login.register') }}
          </el-button>
        </el-form-item>
      </el-form>
      
      <div v-if="error" class="error-message">
        <el-icon><Warning /></el-icon>
        {{ error }}
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import type { FormInstance } from 'element-plus'
import { User, Lock, Key, Warning } from '@element-plus/icons-vue'
import { login } from '@/api/auth'

const router = useRouter()
const { t } = useI18n()
const formRef = ref<FormInstance>()
const loading = ref(false)
const error = ref('')
const captchaUrl = ref('')

const form = reactive({
  username: '',
  password: '',
  captcha: '',
  client_id: ''  // for storing session_id
})

const rules = {
  username: [
    { required: true, message: t('login.rules.username.required'), trigger: 'blur' },
    { min: 3, max: 20, message: t('login.rules.username.length'), trigger: 'blur' }
  ],
  password: [
    { required: true, message: t('login.rules.password.required'), trigger: 'blur' },
    { min: 8, message: t('login.rules.password.min'), trigger: 'blur' }
  ],
  captcha: [
    { required: true, message: t('login.rules.captcha.required'), trigger: 'blur' }
  ]
}

// refresh captcha
const refreshCaptcha = () => {
  // generate random session_id
  form.client_id = Math.random().toString(36).substring(2)
  // add timestamp to prevent cache
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
    ElMessage.success(t('login.success'))
    router.push('/')
  } catch (err: any) {
    if (err.response?.data?.detail) {
      error.value = err.response.data.detail
    } else {
      error.value = t('login.error.default')
    }
    // refresh captcha when login failed
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
  position: relative;
  overflow: hidden;
}

.login-background {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: linear-gradient(135deg, #9ee8c6 0%, #42a399 100%);
  z-index: 1;
}

.login-background-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.3);
}

.login-card {
  width: 100%;
  max-width: 420px;
  position: relative;
  z-index: 2;
  background: rgba(255, 255, 255, 0.95);
  border-radius: 12px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
  border: none;
  padding: 40px;
  animation: slideUp 0.5s ease-out;
}

@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.login-header {
  text-align: center;
  margin-bottom: 40px;
}

.login-logo {
  width: 80px;
  height: 80px;
  margin-bottom: 20px;
}

.login-header h2 {
  margin: 0;
  color: #303133;
  font-size: 24px;
  font-weight: 600;
}

.login-subtitle {
  margin: 8px 0 0;
  color: #909399;
  font-size: 14px;
}

.login-form {
  margin-top: 20px;
}

:deep(.el-input__wrapper) {
  box-shadow: none;
  border: 1px solid #dcdfe6;
  border-radius: 8px;
  padding: 8px 15px;
  transition: all 0.3s;
}

:deep(.el-input__wrapper:hover) {
  border-color: #409eff;
}

:deep(.el-input__wrapper.is-focus) {
  border-color: #409eff;
  box-shadow: 0 0 0 2px rgba(64, 158, 255, 0.1);
}

.login-button {
  width: 100%;
  height: 40px;
  border-radius: 8px;
  font-size: 16px;
  margin-bottom: 16px;
}

.register-button {
  width: 100%;
  height: 40px;
  border-radius: 8px;
  font-size: 16px;
}

.error-message {
  display: flex;
  align-items: center;
  justify-content: center;
  color: #f56c6c;
  margin-top: 16px;
  padding: 12px;
  background-color: #fef0f0;
  border-radius: 8px;
  font-size: 14px;
}

.error-message .el-icon {
  margin-right: 8px;
}

.captcha-container {
  display: flex;
  gap: 12px;
}

.captcha-img-container {
  width: 120px;
  height: 40px;
  border: 1px solid #dcdfe6;
  border-radius: 8px;
  overflow: hidden;
  cursor: pointer;
  transition: all 0.3s;
}

.captcha-img-container:hover {
  border-color: #409eff;
}

.captcha-img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

:deep(.el-form-item) {
  margin-bottom: 24px;
}

:deep(.el-form-item__error) {
  padding-top: 4px;
}
</style> 