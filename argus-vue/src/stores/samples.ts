import { defineStore } from 'pinia'
import {
  getSamples,
  getSampleDetail,
  uploadSample,
  deleteSample,
  updateSample,
  getCommonTags,
  type Sample,
  type SampleDetail,
  type GetSamplesParams,
  type UploadSampleParams
} from '@/api/samples'
import { ElMessage } from 'element-plus'

export const useSamplesStore = defineStore('samples', {
  state: () => ({
    samples: [] as Sample[],
    currentSample: null as SampleDetail | null,
    loading: false,
    detailLoading: false,
    commonTags: [] as string[],
    total: 0,
    currentPage: 1,
    pageSize: 10
  }),

  actions: {
    // 获取样本列表
    async fetchSamples(params?: GetSamplesParams) {
      this.loading = true
      try {
        const response = await getSamples({
          limit: this.pageSize,
          order: -1,
          sort: 'timestamp',
          ...params
        })
        if (response.status === 'success') {
          this.samples = response.data.samples
          this.total = response.data.total || response.data.samples.length
        }
      } catch (error) {
        console.error('获取样本列表失败:', error)
        ElMessage.error('获取样本列表失败')
      } finally {
        this.loading = false
      }
    },

    // 获取样本详情
    async fetchSampleDetail(sha256: string) {
      this.detailLoading = true
      try {
        const response = await getSampleDetail(sha256)
        if (response.status === 'success') {
          this.currentSample = response.data.sample
        }
      } catch (error) {
        console.error('获取样本详情失败:', error)
        ElMessage.error('获取样本详情失败')
      } finally {
        this.detailLoading = false
      }
    },

    // 上传样本
    async uploadSample(params: UploadSampleParams) {
      try {
        const response = await uploadSample(params)
        if (response.status === 'success') {
          ElMessage.success('样本上传成功')
          return response.data.sample
        }
      } catch (error) {
        console.error('样本上传失败:', error)
        ElMessage.error('样本上传失败')
        return null
      }
    },

    // 删除样本
    async deleteSample(sha256: string) {
      try {
        const response = await deleteSample(sha256)
        if (response.status === 'success') {
          ElMessage.success('样本删除成功')
          this.samples = this.samples.filter(sample => sample.sha256_digest !== sha256)
          return true
        }
      } catch (error) {
        console.error('样本删除失败:', error)
        ElMessage.error('样本删除失败')
        return false
      }
    },

    // 更新样本信息
    async updateSample(sha256: string, data: Partial<Sample>) {
      try {
        const response = await updateSample(sha256, data)
        if (response.status === 'success') {
          ElMessage.success('样本信息更新成功')
          const index = this.samples.findIndex(sample => sample.sha256_digest === sha256)
          if (index !== -1) {
            this.samples[index] = response.data.sample
          }
          return response.data.sample
        }
      } catch (error) {
        console.error('样本信息更新失败:', error)
        ElMessage.error('样本信息更新失败')
        return null
      }
    },

    // 获取常用标签
    async fetchCommonTags() {
      try {
        const response = await getCommonTags()
        if (response.status === 'success') {
          this.commonTags = response.data.tags
        }
      } catch (error) {
        console.error('获取常用标签失败:', error)
      }
    },

    // 清除当前样本
    clearCurrentSample() {
      this.currentSample = null
    }
  }
}) 