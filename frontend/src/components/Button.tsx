import React, { forwardRef } from 'react'
import { motion, type HTMLMotionProps } from 'framer-motion'
import { cn } from '../lib/utils'
import { Loader2 } from 'lucide-react'

interface ButtonProps extends Omit<HTMLMotionProps<'button'>, 'ref'> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  size?: 'sm' | 'md' | 'lg'
  loading?: boolean
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', loading, children, disabled, ...props }, ref) => {
    return (
      <motion.button
        ref={ref}
        disabled={disabled || loading}
        whileHover={{ scale: disabled || loading ? 1 : 1.02 }}
        whileTap={{ scale: disabled || loading ? 1 : 0.98 }}
        className={cn(
          'btn inline-flex items-center justify-center gap-2.5 font-semibold relative overflow-hidden group',
          {
            'btn-primary shadow-lg shadow-primary-500/25': variant === 'primary',
            'btn-secondary': variant === 'secondary',
            'bg-transparent text-av-muted hover:text-av-main hover:bg-av-border/10 dark:hover:bg-white/5': variant === 'ghost',
            'bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-500/25 border border-red-500/30': variant === 'danger',
            'px-3 py-2 text-xs rounded-lg': size === 'sm',
            'px-5 py-2.5 text-sm rounded-xl': size === 'md',
            'px-7 py-3.5 text-base rounded-xl': size === 'lg',
          },
          className
        )}
        {...props}
      >
        {variant === 'primary' && !disabled && !loading && (
          <motion.div
            className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent"
            initial={{ x: '-100%' }}
            whileHover={{ x: '100%' }}
            transition={{ duration: 0.6, ease: 'easeInOut' }}
          />
        )}
        
        {loading && (
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
          >
            <Loader2 className="w-4 h-4" />
          </motion.div>
        )}
        <span className="relative z-10">{children as React.ReactNode}</span>
      </motion.button>
    )
  }
)

Button.displayName = 'Button'

export default Button

