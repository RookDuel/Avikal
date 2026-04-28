import { useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Upload, Sparkles } from 'lucide-react'
import { getDroppedPaths } from '../lib/electron'
import { cn } from '../lib/utils'
import Button from './Button'
import FileExplorer from './FileExplorer'

interface FileDropZoneProps {
  onFilesSelected: (files: string[]) => void
  multiple?: boolean
  accept?: string
}

const PARTICLE_POSITIONS = [
  { x: '12%', y: '18%' },
  { x: '82%', y: '20%' },
  { x: '26%', y: '72%' },
  { x: '74%', y: '76%' },
  { x: '48%', y: '28%' },
  { x: '58%', y: '64%' },
]

export default function FileDropZone({ onFilesSelected, multiple = true, accept }: FileDropZoneProps) {
  const [files, setFiles] = useState<string[]>([])
  const [isDragging, setIsDragging] = useState(false)

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    
    const droppedFiles = getDroppedPaths(e.dataTransfer.files)
    const newFiles = multiple ? [...files, ...droppedFiles] : droppedFiles.slice(0, 1)
    setFiles(newFiles)
    onFilesSelected(newFiles)
  }, [files, multiple, onFilesSelected])

  const handleBrowse = async () => {
    try {
      const selected = await window.electron?.openFile({ 
        properties: multiple ? ['openFile', 'multiSelections'] : ['openFile'],
        filters: accept ? [{ name: 'Files', extensions: accept.split(',').map(e => e.trim().replace('.', '')) }] : []
      })
      if (selected && selected.length > 0) {
        const newFiles = multiple ? [...files, ...selected] : selected.slice(0, 1)
        setFiles(newFiles)
        onFilesSelected(newFiles)
      }
    } catch (error) {
      console.error('Error selecting files:', error)
    }
  }

  const removeFile = (index: number) => {
    const newFiles = files.filter((_, i) => i !== index)
    setFiles(newFiles)
    onFilesSelected(newFiles)
  }

  const clearAll = () => {
    setFiles([])
    onFilesSelected([])
  }

  return (
    <div className="space-y-4">
      <motion.div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={handleBrowse}
        whileHover={{ scale: 1.01 }}
        whileTap={{ scale: 0.99 }}
        className={cn(
          'relative border-2 border-dashed rounded-2xl p-16 transition-all cursor-pointer overflow-hidden group',
          isDragging 
            ? 'border-primary-500 bg-primary-500/10 shadow-lg shadow-primary-500/20' 
            : files.length > 0
            ? 'border-primary-600/50 bg-primary-600/5'
            : 'border-av-border hover:border-primary-500/50 hover:bg-av-border/10 dark:hover:bg-white/5'
        )}
      >
        {/* Animated Background */}
        <div className="absolute inset-0 bg-gradient-to-br from-primary-500/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
        
        {/* Animated Particles */}
        <AnimatePresence>
          {isDragging && (
            <>
              {PARTICLE_POSITIONS.map((particle, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, scale: 0, x: '50%', y: '50%' }}
                  animate={{ 
                    opacity: [0, 1, 0],
                    scale: [0, 1.5, 0],
                    x: particle.x,
                    y: particle.y,
                  }}
                  exit={{ opacity: 0 }}
                  transition={{ 
                    duration: 2,
                    repeat: Infinity,
                    delay: i * 0.2,
                    ease: 'easeOut'
                  }}
                  className="absolute w-2 h-2 bg-primary-500 rounded-full"
                />
              ))}
            </>
          )}
        </AnimatePresence>
        
        <div className="relative flex flex-col items-center justify-center text-center space-y-5">
          <motion.div
            animate={{ 
              y: isDragging ? -10 : 0,
              scale: isDragging ? 1.1 : 1,
              rotate: isDragging ? [0, -5, 5, 0] : 0
            }}
            transition={{ 
              y: { type: 'spring', stiffness: 300, damping: 20 },
              rotate: { duration: 0.5, repeat: isDragging ? Infinity : 0 }
            }}
            className="relative"
          >
            <div className={cn(
              'w-20 h-20 rounded-2xl flex items-center justify-center transition-all duration-300',
              isDragging 
                ? 'bg-primary-500/20 shadow-lg shadow-primary-500/30' 
                : 'bg-av-border/10 dark:bg-white/5 group-hover:bg-av-border/20 dark:group-hover:bg-white/10'
            )}>
              <Upload className={cn(
                'w-10 h-10 transition-all duration-300',
                isDragging ? 'text-primary-400' : 'text-av-muted group-hover:text-primary-500'
              )} />
            </div>
            
            {files.length > 0 && (
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                className="absolute -top-2 -right-2 w-8 h-8 bg-primary-500 rounded-full flex items-center justify-center shadow-lg"
              >
                <span className="text-xs font-bold text-white">{files.length}</span>
              </motion.div>
            )}
          </motion.div>
          
          <div className="space-y-2">
            <motion.p 
              animate={{ scale: isDragging ? 1.05 : 1 }}
              className="text-lg font-semibold text-av-main"
            >
              {isDragging ? (
                <span className="flex items-center gap-2">
                  <Sparkles className="w-5 h-5 text-primary-400" />
                  Drop files here
                  <Sparkles className="w-5 h-5 text-primary-400" />
                </span>
              ) : files.length > 0 ? (
                `${files.length} file${files.length > 1 ? 's' : ''} selected`
              ) : (
                'Drop files here'
              )}
            </motion.p>
            <p className="text-sm text-av-muted">
              or click to browse {multiple && '(multiple files supported)'}
            </p>
          </div>
          
          <motion.div
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <Button 
              variant="secondary" 
              size="sm"
              onClick={(e) => {
                e.stopPropagation()
                handleBrowse()
              }}
              className="pointer-events-auto"
            >
              Browse Files
            </Button>
          </motion.div>
        </div>
      </motion.div>

      <AnimatePresence>
        {files.length > 0 && (
          <FileExplorer 
            files={files}
            onRemove={removeFile}
            onClear={clearAll}
          />
        )}
      </AnimatePresence>
    </div>
  )
}
