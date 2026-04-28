import type { ReactNode } from 'react'
import { motion } from 'framer-motion'
import { cn } from '../lib/utils'

interface PageLayoutProps {
  children: ReactNode
  className?: string
  /** Max width variant — defaults to 'lg' (max-w-6xl) */
  maxWidth?: 'sm' | 'md' | 'lg' | 'xl' | 'full'
}

const maxWidthMap = {
  sm: 'max-w-2xl',
  md: 'max-w-4xl',
  lg: 'max-w-6xl',
  xl: 'max-w-7xl',
  full: 'max-w-full',
}

/**
 * Responsive page wrapper used by all top-level pages.
 * Provides consistent padding, max-width, and entry animation.
 */
export default function PageLayout({ children, className, maxWidth = 'lg' }: PageLayoutProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] }}
      className={cn(
        maxWidthMap[maxWidth],
        'mx-auto',
        // Responsive horizontal padding: tighter on small windows, wider on large
        'px-4 sm:px-6 md:px-8',
        // Vertical padding
        'py-6 sm:py-8',
        // Vertical spacing between sections
        'space-y-6',
        className
      )}
    >
      {children}
    </motion.div>
  )
}

/**
 * Two-column responsive grid — stacks to single column on narrow windows.
 */
export function TwoColumnGrid({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn('grid grid-cols-1 lg:grid-cols-2 gap-6', className)}>{children}</div>
  )
}

/**
 * Three-column responsive grid — collapses to 2 then 1 column.
 */
export function ThreeColumnGrid({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn('grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6', className)}>
      {children}
    </div>
  )
}
