// src/hooks/useVirusTotalApiKey.ts
import { ref } from 'vue'
import request from '@/utils/request'
export const useVirusTotalApiKey = () => {
  const apiKey = ref(localStorage.getItem('vt_api_key') || '')
  const isApiKeyAvailable = ref(!!apiKey.value)

  const setApiKey = (key: string) => {
    apiKey.value = key
    localStorage.setItem('vt_api_key', key)
    isApiKeyAvailable.value = true
  }

  const removeApiKey = () => {
    apiKey.value = ''
    localStorage.removeItem('vt_api_key')
    isApiKeyAvailable.value = false
  }

  return {
    apiKey,
    isApiKeyAvailable,
    setApiKey,
    removeApiKey
  }
}

export const uploadFromVirusTotal = async (hash: string) => {
    const { apiKey } = useVirusTotalApiKey()
    
    if (!apiKey.value) {
      throw new Error('VirusTotal API key not configured')
    }
  
    const response = await request.post('/api/virus-total/upload', {
      hash,
      api_key: apiKey.value
    })
    
    return response.data
  }