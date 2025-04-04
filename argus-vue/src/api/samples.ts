import request from '@/utils/request'
import type { Sample, SampleQueryParams } from '@/types/sample'
import type { ApiListResponse } from '@/utils/request'

export interface SampleListResponse {
  data: Sample[]
  total: number
}

export function getSamples(params: SampleQueryParams) {
  return request<ApiListResponse<Sample>>({
    url: '/samples/list',
    method: 'get',
    params
  })
}

export function uploadSample(data: {
  file: File
  tags?: string[]
  description?: string
}) {
  const formData = new FormData()
  formData.append('file', data.file)
  if (data.tags) {
    formData.append('tags', JSON.stringify(data.tags))
  }
  if (data.description) {
    formData.append('description', data.description)
  }

  return request<Sample>({
    url: '/samples/upload',
    method: 'post',
    data: formData,
    headers: {
      'Content-Type': 'multipart/form-data'
    }
  })
}

export function getSample(sha256_digest: string) {
  return request<Sample>({
    url: `/samples/${sha256_digest}`,
    method: 'get'
  })
}

export function deleteSample(sha256_digest: string) {
  return request({
    url: `/samples/${sha256_digest}`,
    method: 'delete'
  })
}

export function downloadSample(sha256_digest: string) {
  return request<{
    download_url: string
    file_name: string
    file_type: string
  }>({
    url: `/samples/${sha256_digest}/download`,
    method: 'get'
  }).catch(error => {
    throw error
  })
} 