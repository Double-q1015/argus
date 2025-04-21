<template>
  <div class="pe-overview-card">
    <div class="section">
      <el-divider content-position="left">Header</el-divider>
      <el-descriptions :column="1" border>
        <el-descriptions-item label="Target Machine">
          <el-text copyable>{{ data.scan.pe?.header?.machine?.type }}</el-text>
        </el-descriptions-item>
        <el-descriptions-item label="Compilation Timestamp">
          <el-text copyable>{{ data.scan.pe?.compile_time }}</el-text>
        </el-descriptions-item>
        <el-descriptions-item label="Entry Point">
          <el-text copyable>{{ data.scan.pe?.address_of_entry_point }}</el-text>
        </el-descriptions-item>
        <el-descriptions-item label="Contained Sections">
          <el-text copyable>{{ data.scan.pe?.sections?.length }}</el-text>
        </el-descriptions-item>
      </el-descriptions>
    </div>

    <div class="section">
      <el-divider content-position="left">Sections</el-divider>
      <el-table :data="sectionData" style="width: 100%" size="small" :border="true">
        <el-table-column prop="name" label="Name" />
        <el-table-column label="Virtual Address">
          <template #default="{ row }">
            {{ row.address.virtual }}
          </template>
        </el-table-column>
        <el-table-column prop="size" label="Virtual Size" />
        <el-table-column label="Raw Size">
          <template #default="{ row }">
            {{ row.address.physical }}
          </template>
        </el-table-column>
        <el-table-column prop="entropy" label="Entropy">
          <template #default="{ row }">
            <span :class="{ 'high-entropy': row.entropy > 7 }">
              {{ row.entropy.toFixed(3) }}
            </span>
          </template>
        </el-table-column>
        <el-table-column prop="md5" label="MD5">
          <template #default="{ row }">
            <el-text copyable>{{ row.md5 }}</el-text>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="section">
      <el-divider content-position="left">Signature Info</el-divider>
      <div class="signature-info">
        <h4>Signature Verification</h4>
        <div class="signature-status">
          <el-icon v-if="data.scan.pe?.security" color="#67C23A"><CircleCheckFilled /></el-icon>
          <el-icon v-else color="#E6A23C"><WarningFilled /></el-icon>
          <span>{{ data.scan.pe?.security ? 'File is signed' : 'File is not signed' }}</span>
        </div>

        <h4>File Version Information</h4>
        <el-descriptions :column="1" border>
          <el-descriptions-item label="Copyright">
            <el-text copyable>{{ data.scan.pe?.file_info?.legal_copyright }}</el-text>
          </el-descriptions-item>
          <el-descriptions-item label="Product">
            <el-text copyable>{{ data.scan.pe?.file_info?.product_name }}</el-text>
          </el-descriptions-item>
          <el-descriptions-item label="Description">
            <el-text copyable>{{ data.scan.pe?.file_info?.file_description }}</el-text>
          </el-descriptions-item>
          <el-descriptions-item label="Original Name">
            <el-text copyable>{{ data.scan.pe?.file_info?.original_filename }}</el-text>
          </el-descriptions-item>
          <el-descriptions-item label="File Version">
            <el-text copyable>{{ data.scan.pe?.file_info?.file_version }}</el-text>
          </el-descriptions-item>
        </el-descriptions>
      </div>
    </div>

    <div class="section">
      <el-divider content-position="left">Imports</el-divider>
      <div class="symbol-list">
        <el-scrollbar max-height="200px">
          <el-space direction="vertical" alignment="stretch" style="width: 100%">
            <el-tag
              v-for="symbol in importedSymbols"
              :key="symbol"
              size="small"
              class="symbol-tag"
            >
              {{ symbol }}
            </el-tag>
          </el-space>
        </el-scrollbar>
      </div>
    </div>

    <div class="section">
      <el-divider content-position="left">Exports</el-divider>
      <div class="symbol-list">
        <el-scrollbar max-height="200px">
          <el-space direction="vertical" alignment="stretch" style="width: 100%">
            <el-tag
              v-for="symbol in exportedSymbols"
              :key="symbol"
              size="small"
              class="symbol-tag"
            >
              {{ symbol }}
            </el-tag>
          </el-space>
        </el-scrollbar>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { computed } from 'vue'
import { CircleCheckFilled, WarningFilled } from '@element-plus/icons-vue'
import type { OverviewCardProps } from '../types'

const props = defineProps<{ data: OverviewCardProps['data'] }>()

interface Section {
  name: string
  address: {
    virtual: number
    physical: number
  }
  size: number
  entropy: number
  md5: string
}

const sectionData = computed(() =>
    props.data.scan.pe?.sections?.map((section: Section, index: number) => ({
      key: index,
      name: section.name,
      address: section.address,
      size: section.size,
      entropy: section.entropy,
      md5: section.md5,
    })) || []
)



const importedSymbols = computed(() => props.data.scan.pe?.symbols?.imported || [])
const exportedSymbols = computed(() => props.data.scan.pe?.symbols?.exported || [])
</script>

<style scoped>
.pe-overview-card {
  font-family: var(--el-font-family);
}

.section {
  margin-bottom: 20px;
}

.signature-info {
  padding: 16px;
}

.signature-info h4 {
  font-size: var(--el-font-size-small);
  margin: 8px 0;
  color: var(--el-text-color-primary);
}

.signature-status {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 8px 0;
  font-size: var(--el-font-size-small);
}

.symbol-list {
  padding: 8px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 4px;
}

.symbol-tag {
  width: 100%;
  text-align: left;
  font-family: monospace;
}

.high-entropy {
  color: var(--el-color-danger);
}

:deep(.el-descriptions__label) {
  width: 150px;
  color: var(--el-text-color-regular);
}

:deep(.el-table) {
  font-size: var(--el-font-size-small);
}

:deep(.el-tag) {
  font-size: var(--el-font-size-small);
}
</style>
  