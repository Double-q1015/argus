<template>
    <div class="vt-uploader">
      <el-input
        v-model="hash"
        placeholder="Enter MD5, SHA1 or SHA256 hash"
        :prefix-icon="Search"
        class="mb-3"
      />
      
      <el-button 
        type="primary" 
        :loading="loading"
        :disabled="!isApiKeyAvailable"
        @click="handleUpload"
      >
        Get from VirusTotal
      </el-button>
  
      <div v-if="!isApiKeyAvailable" class="vt-overlay">
        <h3>VirusTotal API key not configured</h3>
        <p>Please configure the API key in the settings</p>
      </div>
    </div>
  </template>
  
<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import { useVirusTotalApiKey, uploadFromVirusTotal } from '@/api/virustotal'

const props = defineProps<{
onSuccess?: () => void
}>()

const hash = ref('')
const loading = ref(false)
const { isApiKeyAvailable } = useVirusTotalApiKey()

const handleUpload = async () => {
if (!hash.value) {
    ElMessage.warning('Please enter the hash value')
    return
}

loading.value = true
try {
    await uploadFromVirusTotal(hash.value)
    ElMessage.success('Get from VirusTotal successfully')
    props.onSuccess?.()
} catch (error) {
    ElMessage.error('Get from VirusTotal failed')
} finally {
    loading.value = false
}
}
</script>
  
<style scoped>
.vt-uploader {
position: relative;
}

.vt-overlay {
position: absolute;
top: 0;
left: 0;
right: 0;
bottom: 0;
background-color: rgba(255, 255, 255, 0.8);
display: flex;
flex-direction: column;
align-items: center;
justify-content: center;
border-radius: 4px;
text-align: center;
color: #909399;
padding: 20px;
}

.mb-3 {
margin-bottom: 12px;
}
</style>