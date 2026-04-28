import { motion, AnimatePresence } from 'framer-motion'
import { File, Folder, X, FileText, FileImage, FileVideo, FileArchive, FileCode, type LucideIcon } from 'lucide-react'
import { useState } from 'react'

interface FileExplorerProps {
  files: string[]
  onRemove: (index: number) => void
  onClear: () => void
}

function getFileIcon(filename: string) {
  const ext = filename.split('.').pop()?.toLowerCase()
  
  const iconMap: Record<string, LucideIcon> = {
    // Images
    jpg: FileImage, jpeg: FileImage, png: FileImage, gif: FileImage, svg: FileImage, webp: FileImage,
    // Videos
    mp4: FileVideo, avi: FileVideo, mov: FileVideo, mkv: FileVideo, webm: FileVideo,
    // Archives
    zip: FileArchive, rar: FileArchive, '7z': FileArchive, tar: FileArchive, gz: FileArchive,
    // Code
    js: FileCode, ts: FileCode, jsx: FileCode, tsx: FileCode, py: FileCode, java: FileCode,
    cpp: FileCode, c: FileCode, go: FileCode, rs: FileCode, php: FileCode, rb: FileCode,
    // Documents
    pdf: FileText, doc: FileText, docx: FileText, txt: FileText, md: FileText,
  }
  
  return iconMap[ext || ''] || File
}

function renderFileTypeIcon(filename: string, className: string) {
  const icon = getFileIcon(filename)

  switch (icon) {
    case FileImage:
      return <FileImage className={className} />
    case FileVideo:
      return <FileVideo className={className} />
    case FileArchive:
      return <FileArchive className={className} />
    case FileCode:
      return <FileCode className={className} />
    case FileText:
      return <FileText className={className} />
    default:
      return <File className={className} />
  }
}

function getFileColor(filename: string) {
  const ext = filename.split('.').pop()?.toLowerCase()
  
  const colorMap: Record<string, string> = {
    // Images - Purple
    jpg: 'text-purple-400', jpeg: 'text-purple-400', png: 'text-purple-400', gif: 'text-purple-400', 
    svg: 'text-purple-400', webp: 'text-purple-400',
    // Videos - Red
    mp4: 'text-red-400', avi: 'text-red-400', mov: 'text-red-400', mkv: 'text-red-400', webm: 'text-red-400',
    // Archives - Yellow
    zip: 'text-yellow-400', rar: 'text-yellow-400', '7z': 'text-yellow-400', tar: 'text-yellow-400', gz: 'text-yellow-400',
    // Code - Blue
    js: 'text-blue-400', ts: 'text-blue-400', jsx: 'text-blue-400', tsx: 'text-blue-400', 
    py: 'text-blue-400', java: 'text-blue-400', cpp: 'text-blue-400', c: 'text-blue-400',
    // Documents - Green
    pdf: 'text-green-400', doc: 'text-green-400', docx: 'text-green-400', txt: 'text-green-400', md: 'text-green-400',
  }
  
  return colorMap[ext || ''] || 'text-primary-400'
}

function FileTreeItem({ file, index, onRemove }: { file: string; index: number; onRemove: (index: number) => void }) {
  const [isHovered, setIsHovered] = useState(false)
  const fileName = file.split('\\').pop() || file.split('/').pop() || file
  const color = getFileColor(fileName)
  
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20, transition: { duration: 0.2 } }}
      transition={{ type: 'spring', stiffness: 500, damping: 30 }}
      onHoverStart={() => setIsHovered(true)}
      onHoverEnd={() => setIsHovered(false)}
      className="group relative"
    >
      <div className="flex items-center gap-3 p-3 rounded-xl bg-av-border/10 dark:bg-white/5 border border-av-border/40 hover:border-av-border hover:bg-av-border/15 dark:hover:bg-white/10 transition-all">
        <motion.div
          animate={{ scale: isHovered ? 1.1 : 1, rotate: isHovered ? 5 : 0 }}
          transition={{ type: 'spring', stiffness: 400, damping: 20 }}
        >
          {renderFileTypeIcon(fileName, `w-5 h-5 ${color} flex-shrink-0`)}
        </motion.div>
        
        <div className="flex-1 min-w-0">
          <p className="text-sm text-av-main truncate font-medium">{fileName}</p>
          <p className="text-xs text-av-muted truncate mt-0.5">{file}</p>
        </div>
        
        <AnimatePresence>
          {isHovered && (
            <motion.button
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              whileHover={{ scale: 1.1, backgroundColor: 'rgba(239, 68, 68, 0.2)' }}
              whileTap={{ scale: 0.9 }}
              onClick={() => onRemove(index)}
              className="p-1.5 rounded-lg bg-av-border/10 dark:bg-white/5 hover:bg-red-500/20 transition-colors"
            >
              <X className="w-4 h-4 text-av-muted hover:text-red-400 transition-colors" />
            </motion.button>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  )
}

export default function FileExplorer({ files, onRemove, onClear }: FileExplorerProps) {
  if (files.length === 0) return null
  
  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-3"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <motion.div
            animate={{ rotate: [0, 10, -10, 0] }}
            transition={{ duration: 0.5 }}
          >
            <Folder className="w-4 h-4 text-primary-500" />
          </motion.div>
          <span className="text-sm font-semibold text-av-main">
            Selected Files ({files.length})
          </span>
        </div>
        
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={onClear}
          className="text-xs text-av-muted hover:text-red-400 transition-colors px-3 py-1.5 rounded-lg hover:bg-red-500/10"
        >
          Clear All
        </motion.button>
      </div>
      
      <motion.div 
        layout
        className="space-y-2 max-h-80 overflow-y-auto pr-2 custom-scrollbar"
      >
        <AnimatePresence mode="popLayout">
          {files.map((file, index) => (
            <FileTreeItem
              key={`${file}-${index}`}
              file={file}
              index={index}
              onRemove={onRemove}
            />
          ))}
        </AnimatePresence>
      </motion.div>
    </motion.div>
  )
}
