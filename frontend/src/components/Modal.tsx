import type { ReactNode } from 'react'
import { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X } from 'lucide-react'
import { cn } from '../lib/utils'

interface ModalProps {
  isOpen: boolean
  onClose: () => void
  title?: string
  children: ReactNode
  className?: string
  /** Prevent closing when clicking the backdrop */
  disableBackdropClose?: boolean
}

export default function Modal({
  isOpen,
  onClose,
  title,
  children,
  className,
  disableBackdropClose = false,
}: ModalProps) {
  // Close on Escape key
  useEffect(() => {
    if (!isOpen) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [isOpen, onClose])

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="theme-backdrop fixed inset-0 z-50"
            onClick={disableBackdropClose ? undefined : onClose}
            aria-hidden="true"
          />

          {/* Dialog */}
          <motion.div
            key="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby={title ? 'modal-title' : undefined}
            initial={{ opacity: 0, scale: 0.95, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 10 }}
            transition={{ duration: 0.2, ease: [0.4, 0, 0.2, 1] }}
            className={cn(
              'fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50',
              'w-full max-w-lg',
              'bg-av-surface border border-av-border rounded-2xl shadow-2xl',
              'max-h-[90vh] overflow-y-auto',
              className
            )}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            {title && (
              <div className="flex items-center justify-between px-6 py-4 border-b border-av-border/60">
                <h2 id="modal-title" className="text-lg font-semibold text-av-main">
                  {title}
                </h2>
                <button
                  onClick={onClose}
                  aria-label="Close modal"
                  className="w-8 h-8 rounded-lg flex items-center justify-center text-av-muted hover:text-av-main hover:bg-av-border/10 dark:hover:bg-white/5 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            )}

            {/* Body */}
            <div className="p-6">{children}</div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  )
}
