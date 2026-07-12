import { Upload, X } from 'lucide-react'
import { useCallback, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { uploadService } from '../services/uploadService'

interface UploadModalProps {
  open: boolean
  onClose: () => void
}

export function UploadModal({ open, onClose }: UploadModalProps) {
  const [files, setFiles] = useState<File[]>([])
  const [dragOver, setDragOver] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: uploadService.uploadSbom,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
      queryClient.invalidateQueries({ queryKey: ['applications'] })
      queryClient.invalidateQueries({ queryKey: ['report'] })
      queryClient.invalidateQueries({ queryKey: ['executive-summary'] })
      setFiles([])
      onClose()
    },
  })

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const dropped = Array.from(e.dataTransfer.files).filter(
      (f) => f.name.endsWith('.json') || f.type === 'application/json',
    )
    setFiles((prev) => [...prev, ...dropped])
  }, [])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-lg rounded-xl border border-cyber-700 bg-cyber-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-bold text-white">Upload SBOM</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => inputRef.current?.click()}
          className={`cursor-pointer rounded-xl border-2 border-dashed p-8 text-center transition-colors ${
            dragOver ? 'border-cyber-accent bg-cyber-accent/5' : 'border-cyber-600 hover:border-cyber-accent/50'
          }`}
        >
          <Upload className="mx-auto mb-3 h-10 w-10 text-cyber-accent" />
          <p className="text-sm text-slate-300">Drop CycloneDX JSON files here or click to browse</p>
          <input
            ref={inputRef}
            type="file"
            accept=".json,application/json"
            multiple
            className="hidden"
            onChange={(e) => {
              if (e.target.files) setFiles(Array.from(e.target.files))
            }}
          />
        </div>

        {files.length > 0 && (
          <ul className="mt-4 space-y-1">
            {files.map((f) => (
              <li key={f.name} className="text-sm text-slate-400">{f.name}</li>
            ))}
          </ul>
        )}

        {mutation.isError && (
          <p className="mt-3 text-sm text-risk-critical">
            {(mutation.error as Error).message || 'Upload failed'}
          </p>
        )}

        <div className="mt-6 flex justify-end gap-3">
          <button onClick={onClose} className="rounded-lg px-4 py-2 text-sm text-slate-400 hover:text-white">
            Cancel
          </button>
          <button
            disabled={!files.length || mutation.isPending}
            onClick={() => mutation.mutate(files)}
            className="rounded-lg bg-cyber-accent px-4 py-2 text-sm font-medium text-cyber-950 hover:bg-cyber-accent-dim disabled:opacity-50"
          >
            {mutation.isPending ? 'Uploading...' : 'Analyze SBOM'}
          </button>
        </div>
      </div>
    </div>
  )
}
