<template>
    <el-card class="collapse-card" :body-style="{ padding: '0px' }">
      <div class="collapse-header">
        <div class="header-content">
          <h3>{{ title }}</h3>
          <div v-if="description" class="description">
            <p v-for="(desc, index) in description" :key="index">{{ desc }}</p>
          </div>
          <div v-if="tags && tags.length" class="tags">
            <el-tag
              v-for="(tag, index) in tags"
              :key="index"
              :type="tag.color"
              size="small"
            >
              {{ tag.label }}
            </el-tag>
          </div>
        </div>
        <el-button
          class="expand-button"
          :class="{ 'is-expanded': expanded }"
          :icon="expanded ? CaretTop : CaretBottom"
          @click="handleExpandClick"
          text
        />
      </div>
      <div v-if="expanded" class="collapse-content">
        <slot></slot>
      </div>
    </el-card>
  </template>
  
  <script setup lang="ts">
  import { CaretTop, CaretBottom } from '@element-plus/icons-vue'
  interface Tag {
    label: string
    color?: 'success' | 'warning' | 'danger' | 'info' | 'error'
  }
  
  interface Props {
    title: string
    description?: string[]
    tags?: Tag[]
    expanded: boolean
  }
  
  const props = defineProps<Props>()
  const emit = defineEmits<{
    (e: 'update:expanded', value: boolean): void
    (e: 'expand-change', value: boolean): void
  }>()
  
  const handleExpandClick = () => {
    const newValue = !props.expanded
    emit('update:expanded', newValue)
    emit('expand-change', newValue)
  }
  </script>
  
  <style scoped>
  .collapse-card {
    width: 100%;
    margin-bottom: 16px;
    border-radius: 8px;
  }
  
  .collapse-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding: 12px 16px;
    border-bottom: 1px solid var(--el-border-color-light);
  }
  
  .header-content {
    flex: 1;
  }
  
  .collapse-header h3 {
    margin: 0;
    font-size: 16px;
    color: var(--el-text-color-primary);
  }
  
  .description {
    margin-top: 8px;
  }
  
  .description p {
    margin: 4px 0;
    color: var(--el-text-color-secondary);
    font-size: 14px;
  }
  
  .tags {
    margin-top: 8px;
    display: flex;
    gap: 8px;
  }
  
  .expand-button {
    color: black;
    padding: 8px;
    border-radius: 4px;
    transition: all 0.3s;
  }
  
  .expand-button:hover {
    background-color: var(--el-color-primary-light-9);
    color: var(--el-color-primary);
  }
  
  .expand-button.is-expanded {
    transform: rotate(0);
    color: var(--el-color-primary);
  }
  
  .expand-button:not(.is-expanded) {
    transform: rotate(0);
  }
  
  .collapse-content {
    padding: 16px;
  }
  </style> 