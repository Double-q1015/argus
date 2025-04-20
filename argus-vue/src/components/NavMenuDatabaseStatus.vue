<template>
  <div>
      <el-tooltip :content="statusTooltip" placement="top">
        <el-avatar
          :style="{ backgroundColor: isDatabaseOnline ? '#52c41a' : '#eb2f96' }"
        >
          <el-icon><Monitor /></el-icon>
        </el-avatar>
      </el-tooltip>
    </div>
</template>
  
<script setup lang="ts">
import { computed } from 'vue'
import { Monitor } from '@element-plus/icons-vue'
import { useDatabaseStatus } from '@/hooks/useDatabaseStatus'

const { data } = useDatabaseStatus()

const isDatabaseOnline = computed(() => {
  return data.value?.data?.message === 'Database is reachable'
})

const statusTooltip = computed(() => {
return isDatabaseOnline.value
    ? 'Database is available.'
    : 'Cannot connect to database. File submission may not work. Contact your administrator for details.'
})
</script>

<style scoped>
.el-avatar {
cursor: pointer;
}
</style>