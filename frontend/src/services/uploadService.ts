import api from './api'
import type { UploadResponse } from '../types'

export const uploadService = {
  uploadSbom: async (files: File[]): Promise<UploadResponse> => {
    const formData = new FormData()
    files.forEach((file) => formData.append('files', file))
    const { data } = await api.post<UploadResponse>('/upload-sbom', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data
  },
}
