import { forwardRef, useState } from 'react'
import { motion, AnimatePresence, type HTMLMotionProps } from 'framer-motion'
import { cn } from '../lib/utils'

interface InputProps extends Omit<HTMLMotionProps<'input'>, 'ref'> {
  label?: string
  error?: string
}

const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, label, error, ...props }, ref) => {
    const [isFocused, setIsFocused] = useState(false)
    
    return (
      <div className="w-full">
        {label && (
          <motion.label 
            initial={{ opacity: 0, y: -5 }}
            animate={{ opacity: 1, y: 0 }}
            className="block text-sm font-medium text-av-muted mb-2"
          >
            {label}
          </motion.label>
        )}
        <div className="relative">
          <motion.input
            ref={ref}
            onFocus={() => setIsFocused(true)}
            onBlur={() => setIsFocused(false)}
            animate={{
              scale: isFocused ? 1.01 : 1,
            }}
            transition={{ type: 'spring', stiffness: 400, damping: 30 }}
            className={cn(
              'input',
              error && 'border-red-500 focus:ring-red-500',
              className
            )}
            {...props}
          />
          <AnimatePresence>
            {isFocused && (
              <motion.div
                initial={{ scaleX: 0 }}
                animate={{ scaleX: 1 }}
                exit={{ scaleX: 0 }}
                className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-primary-500 to-primary-600 origin-left"
              />
            )}
          </AnimatePresence>
        </div>
        <AnimatePresence>
          {error && (
            <motion.p
              initial={{ opacity: 0, y: -5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              className="mt-1.5 text-xs text-red-400 flex items-center gap-1"
            >
              <span className="w-1 h-1 bg-red-400 rounded-full" />
              {error}
            </motion.p>
          )}
        </AnimatePresence>
      </div>
    )
  }
)

Input.displayName = 'Input'

export default Input

