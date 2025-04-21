<template>
  <div>
    <VirusTotalAugmentDrawer
      :resource="selectedResource"
      :open="vtDrawerVisible"
      @close="vtDrawerVisible = false"
    />
    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="18">
        <a-typography-text type="secondary" style="font-size: 12px; margin-bottom: 8px">
          Search Filter
        </a-typography-text>
        <a-input-search
          placeholder="Search by File Name, Submission Description, Uploader, or YARA Matches..."
          @change="debouncedSearchChange"
          style="font-size: 12px"
        />
      </a-col>
      <a-col :span="6">
        <a-typography-text type="secondary" style="font-size: 12px; margin-bottom: 8px">
          Exclude Submitters
        </a-typography-text>
        <a-select
          mode="tags"
          style="width: 100%; font-size: 12px"
          placeholder="Submitters to exclude..."
          v-model:value="excludedSubmitters"
          @change="handleExcludedSubmitterChange"
        />
      </a-col>
    </a-row>
    <div style="min-height: 570px">
      <a-table
        size="small"
        :loading="isLoading"
        :columns="columns"
        :data-source="result?.items || []"
        :pagination="pagination"
        :row-key="record => record.id"
        @change="handleTableChange"
      />
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, watch, computed } from 'vue'
import { debounce } from 'lodash-es'
import { useVirusTotalApiKey } from '@/hooks/useVirusTotalApiKey'
import { useMessageApi } from '@/providers/MessageProvider'
import { useSearchScans } from '@/hooks/useSearchScans'
import { getIconConfig } from '@/utils/iconMappingTable'
import VirusTotalAugmentDrawer from '@/components/VirusTotal/VirusTotalAugmentDrawer.vue'
import { APP_CONFIG } from '@/config'

const searchQuery = ref('')
const excludedSubmitters = ref([...APP_CONFIG.DEFAULT_EXCLUDED_SUBMITTERS])
const sorter = ref({ field: 'submitted_at', order: 'descend' })
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const vtDrawerVisible = ref(false)
const selectedResource = ref(null)

const { isApiKeyAvailable } = useVirusTotalApiKey()
const message = useMessageApi()
const { data: result, isLoading } = useSearchScans({
  searchQuery,
  page: currentPage,
  pageSize,
  sortField: computed(() => sorter.value.field),
  sortOrder: computed(() => sorter.value.order),
  excludeSubmitters: excludedSubmitters,
})

watch(() => result.value?.total, (val) => {
  if (val > 0) total.value = val
})

const pagination = computed(() => ({
  current: currentPage.value,
  pageSize: pageSize.value,
  total: total.value,
  showSizeChanger: true,
  showTotal: (total) => `Total ${total} items`,
}))

const handleVtOpen = (sha256Hash) => {
  if (isApiKeyAvailable.value) {
    selectedResource.value = sha256Hash
    vtDrawerVisible.value = true
  }
}

const handleSearchChange = (e) => {
  searchQuery.value = e.target.value
  currentPage.value = 1
}

const handleExcludedSubmitterChange = (value) => {
  excludedSubmitters.value = value
  currentPage.value = 1
}

const handleTableChange = (pagination, _filters, newSorter) => {
  if (newSorter.field && newSorter.order) {
    sorter.value = {
      field: newSorter.field,
      order: newSorter.order,
    }
  } else {
    sorter.value = { field: 'submitted_at', order: 'descend' }
  }
  currentPage.value = pagination.current
  pageSize.value = pagination.pageSize
}

const debouncedSearchChange = debounce(handleSearchChange, 300)

const formatFileSize = (fileSize) => {
  let unit = 'B'
  let formattedSize
  if (fileSize >= 1024 * 1024) {
    formattedSize = (fileSize / (1024 * 1024)).toFixed(2)
    unit = 'MB'
  } else if (fileSize >= 1024) {
    formattedSize = (fileSize / 1024).toFixed(2)
    unit = 'KB'
  } else {
    formattedSize = fileSize
  }
  return `${formattedSize}${unit}`
}

// Columns will need conversion as custom renderers with JSX or slots
const columns = ref([]) // TODO: define columns using Vue render function or scoped slots.
</script>

<style scoped></style>
