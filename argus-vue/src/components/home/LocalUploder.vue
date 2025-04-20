<template>
    <div class="upload-form">
        <el-input
        v-model="description"
        placeholder="(Optional) File description..."
        :prefix-icon="Message"
        />
        
        <el-input
        v-model="password"
        type="password"
        placeholder="(Optional) File password..."
        :prefix-icon="Lock"
        class="mt-3"
        />
        
        <el-upload
        class="upload-area mt-3"
        drag
        action="/api/upload"
        :data="{ description, password }"
        :on-success="handleSuccess"
        :on-error="handleError"
        multiple
        >
        <el-icon class="el-icon--upload"><upload-filled /></el-icon>
        <div class="el-upload__text">
            Drag and drop files here or <em>click to upload</em>
        </div>
        </el-upload>
    </div>
</template>

<script setup lang="ts">
import { Message, Lock, UploadFilled } from '@element-plus/icons-vue'
import { ref } from 'vue'
import { ElMessage } from 'element-plus'

const description = ref('')
const password = ref('')

const handleSuccess = (response: any, file: any) => {
    ElMessage.success('Upload successfully')
}

const handleError = (error: any) => {
    ElMessage.error('Upload failed')
}
</script>

<style scoped>
.upload-form {
    margin-bottom: 20px;
}

.upload-area {
    width: 100%;
}
</style>