import { motion } from 'framer-motion'
import { cn } from '../lib/utils'

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg'
  className?: string
  label?: string
}

const sizeMap = {
  sm: { outer: 'w-6 h-6', inner: 'w-4 h-4', text: 'text-xs' },
  md: { outer: 'w-10 h-10', inner: 'w-6 h-6', text: 'text-sm' },
  lg: { outer: 'w-16 h-16', inner: 'w-10 h-10', text: 'text-base' },
}

export default function LoadingSpinner({ size = 'md', className, label }: LoadingSpinnerProps) {
  const s = sizeMap[size]

  return (
    <div
      role="status"
      aria-label={label ?? 'Loading'}
      className={cn('flex flex-col items-center justify-center gap-3', className)}
    >
      <div className={cn('relative', s.outer)}>
        {/* Outer ring */}
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1.2, repeat: Infinity, ease: 'linear' }}
          className={cn(
            'absolute inset-0 rounded-full border-2 border-transparent border-t-primary-500',
            s.outer
          )}
        />
        {/* Inner ring (counter-rotate for visual depth) */}
        <motion.div
          animate={{ rotate: -360 }}
          transition={{ duration: 1.8, repeat: Infinity, ease: 'linear' }}
          className={cn(
            'absolute inset-1 rounded-full border-2 border-transparent border-t-primary-400/50',
            s.inner
          )}
        />
      </div>

      {label && (
        <span className={cn('text-av-muted font-medium', s.text)}>{label}</span>
      )}
    </div>
  )
}
