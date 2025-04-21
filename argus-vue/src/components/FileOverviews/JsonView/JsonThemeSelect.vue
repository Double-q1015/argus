<template>
  <div class="json-theme-select">
    <el-select
      v-model="selectedTheme"
      placeholder="选择主题"
      @change="handleThemeChange"
    >
      <el-option
        v-for="theme in themes"
        :key="theme.value"
        :label="theme.label"
        :value="theme.value"
      />
    </el-select>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

interface Theme {
  label: string
  value: string
}

const themes: Theme[] = [
  { label: '默认', value: 'default' },
  { label: '暗色', value: 'dark' },
  { label: '亮色', value: 'light' },
  { label: 'Monokai', value: 'monokai' },
  { label: 'Solarized', value: 'solarized' },
  { label: 'Material', value: 'material' }
]

const emit = defineEmits<{
  (e: 'themeChange', theme: string): void
}>()

const selectedTheme = ref('default')

const handleThemeChange = (theme: string) => {
  emit('themeChange', theme)
}
</script>

<style scoped>
.json-theme-select {
  margin-bottom: 16px;
}

:deep(.el-select) {
  width: 200px;
}
</style> 