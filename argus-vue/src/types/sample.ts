export interface PEInfo {
  compile_time: string
  entry_point: string
  platform: string
  is_signed: boolean
  company_name: string
  product_name: string
  original_filename: string
  pdb_path: string
  sections: Array<{
    name: string
    virtual_address: number
    virtual_size: number
    raw_size: number
    entropy: number
    characteristics: string
  }>
  imports: Array<{
    dll: string
    functions: string[]
  }>
}

export interface Resource {
  type: string
  language: string
  size: number
  offset: number
}

export interface Sample {
  sha256_digest: string
  md5_digest: string
  ssdeep_hash: string
  file_name: string
  file_path: string
  file_size: number
  file_type: string
  upload_time: string
  analysis_time: string
  tags: string[]
  description?: string
  uploader: string
  analysis_status: 'pending' | 'analyzing' | 'completed' | 'failed'
  analysis_results?: any
  pe_info?: PEInfo
  resources?: Resource[]
}

export interface SampleQueryParams {
  skip?: number
  limit?: number
  search?: string
}

export interface SampleResponse {
  data: Sample[]
  total: number
}

export type SampleDetail = Sample 