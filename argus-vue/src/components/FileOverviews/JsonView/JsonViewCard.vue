<template>
  <div class="json-view-card">
    <div class="toolbar">
      <json-theme-select @theme-change="handleThemeChange" />
      <div class="toolbar-actions">
        <el-button-group>
          <el-button
            :icon="expanded ? 'el-icon-minus' : 'el-icon-plus'"
            @click="toggleExpand"
          >
            {{ expanded ? '折叠' : '展开' }}
          </el-button>
          <el-button
            icon="el-icon-copy-document"
            @click="copyToClipboard"
          >
            复制
          </el-button>
        </el-button-group>
      </div>
    </div>

    <div class="json-viewer" ref="jsonViewerRef">
      <vue-json-pretty
        :data="jsonData"
        :deep="2"
        :show-length="true"
        :show-line="true"
        :theme="currentTheme"
        @click="handleNodeClick"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import VueJsonPretty from 'vue-json-pretty'
import 'vue-json-pretty/lib/styles.css'
import { ElMessage } from 'element-plus'
import JsonThemeSelect from './JsonThemeSelect.vue'
import type { OverviewCardProps } from '../types'

const props = defineProps<OverviewCardProps>()

const jsonViewerRef = ref<HTMLElement | null>(null)
const expanded = ref(false)
const currentTheme = ref('default')

const jsonData = computed(() => {
  try {
    return typeof props.data === 'string' 
      ? JSON.parse(props.data)
      : props.data
  } catch (error) {
    console.error('JSON parsing error:', error)
    return props.data
  }
})

const handleThemeChange = (theme: string) => {
  currentTheme.value = theme
}

const toggleExpand = () => {
  expanded.value = !expanded.value
  const jsonViewer = jsonViewerRef.value?.querySelector('.vjs-tree')
  if (jsonViewer) {
    const buttons = jsonViewer.querySelectorAll('.vjs-tree__node:not(.has-value) .vjs-tree__bracket')
    buttons.forEach((button: Element) => {
      if (expanded.value !== (button.parentElement?.classList.contains('is-expanded') ?? false)) {
        ;(button as HTMLElement).click()
      }
    })
  }
}

const copyToClipboard = async () => {
  try {
    const jsonString = JSON.stringify(jsonData.value, null, 2)
    await navigator.clipboard.writeText(jsonString)
    ElMessage.success('已复制到剪贴板')
  } catch (error) {
    console.error('Copy failed:', error)
    ElMessage.error('复制失败')
  }
}

const handleNodeClick = (node: any) => {
  console.log('Node clicked:', node)
}
</script>

<style scoped>
.json-view-card {
  width: 100%;
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.toolbar-actions {
  display: flex;
  gap: 8px;
}

.json-viewer {
  border: 1px solid var(--el-border-color-light);
  border-radius: 4px;
  padding: 16px;
  background-color: var(--el-bg-color);
  overflow: auto;
  max-height: 600px;
}

:deep(.vjs-tree) {
  font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 14px;
  line-height: 1.5;
}

:deep(.vjs-tree__node) {
  cursor: pointer;
}

:deep(.vjs-tree__bracket) {
  color: var(--el-text-color-primary);
}

:deep(.vjs-tree__value) {
  color: var(--el-text-color-regular);
}

:deep(.vjs-tree__key) {
  color: var(--el-color-primary);
}
</style> 