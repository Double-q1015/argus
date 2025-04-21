<template>
    <CollapseCard
      v-if="selectedNodeData?.scan?.pe"
      :title="'Executable Information'"
      :description="[
        `Product: ${productName}`,
        `Compiled: ${compileTime}`
      ]"
      :tags="[
        {
          label: signedLabel,
          color: isSigned ? 'success' : 'error'
        }
      ]"
      v-model:expanded="localExpanded"
      @expand-change="handleExpandChange"
    >
      <PeOverviewCard :data="selectedNodeData" />
    </CollapseCard>
  </template>
  
  <script setup lang="ts">
  import { computed, ref, watch } from 'vue'
  import CollapseCard from '@/components/CollapseCard.vue'
  import PeOverviewCard from './PeOverviewCard.vue'
  import type { OverviewLandingProps } from '../types'
  
  const props = defineProps<{
    expanded: boolean
    selectedNodeData: OverviewLandingProps['selectedNodeData']
  }>()
  
  const emit = defineEmits<{
    (e: 'expand-change', value: boolean): void
  }>()
  
  const localExpanded = ref(props.expanded)
  
  watch(() => props.expanded, (newValue) => {
    localExpanded.value = newValue
  })
  
  const handleExpandChange = (value: boolean) => {
    emit('expand-change', value)
  }
  
  const selectedNodeData = props.selectedNodeData
  
  const peInfo = selectedNodeData?.scan?.pe
  const fileInfo = peInfo?.file_info
  const compileTime = peInfo?.compile_time
  const isSigned = peInfo?.security ?? false
  
  const productName = fileInfo?.product_name ?? ''
  const signedLabel = computed(() => (isSigned ? 'Signed' : 'Not Signed'))
  </script>
  