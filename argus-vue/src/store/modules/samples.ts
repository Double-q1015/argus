import { defineStore } from 'pinia'
import { getSamples, getSampleById, createSample, updateSample, deleteSample } from '@/api/samples'
import type { Sample } from '@/api/samples'

export const useSamplesStore = defineStore('samples', {
  state: () => ({
    samples: [] as Sample[],
    currentSample: null as Sample | null,
    loading: false,
    error: null as string | null
  }),
  
  getters: {
    getSampleById: (state) => (id: string) => {
      return state.samples.find(sample => sample.sha256_digest === id)
    }
  },
  
  actions: {
    async fetchSamples(params = { limit: 10, order: -1, sort: 'timestamp' }) {
      this.loading = true
      this.error = null
      try {
        const response = await getSamples(params)
        if (response.status === 'success') {
          this.samples = response.data.samples
        }
      } catch (error) {
        this.error = error instanceof Error ? error.message : '获取样本列表失败'
      } finally {
        this.loading = false
      }
    },

    async fetchSampleById(id: string) {
      this.loading = true
      this.error = null
      try {
        const response = await getSampleById(id)
        if (response.status === 'success') {
          this.currentSample = response.data.sample
        }
      } catch (error) {
        this.error = error instanceof Error ? error.message : '获取样本详情失败'
      } finally {
        this.loading = false
      }
    },

    async createSample(sample: Partial<Sample>) {
      this.loading = true
      this.error = null
      try {
        const response = await createSample(sample)
        if (response.status === 'success') {
          this.samples.unshift(response.data.sample)
          return response.data.sample
        }
      } catch (error) {
        this.error = error instanceof Error ? error.message : '创建样本失败'
        throw error
      } finally {
        this.loading = false
      }
    },

    async updateSample(id: string, sample: Partial<Sample>) {
      this.loading = true
      this.error = null
      try {
        const response = await updateSample(id, sample)
        if (response.status === 'success') {
          const index = this.samples.findIndex(s => s.sha256_digest === id)
          if (index !== -1) {
            this.samples[index] = response.data.sample
          }
          if (this.currentSample?.sha256_digest === id) {
            this.currentSample = response.data.sample
          }
          return response.data.sample
        }
      } catch (error) {
        this.error = error instanceof Error ? error.message : '更新样本失败'
        throw error
      } finally {
        this.loading = false
      }
    },

    async deleteSample(id: string) {
      this.loading = true
      this.error = null
      try {
        const response = await deleteSample(id)
        if (response.status === 'success') {
          this.samples = this.samples.filter(s => s.sha256_digest !== id)
          if (this.currentSample?.sha256_digest === id) {
            this.currentSample = null
          }
        }
      } catch (error) {
        this.error = error instanceof Error ? error.message : '删除样本失败'
        throw error
      } finally {
        this.loading = false
      }
    }
  }
}) 