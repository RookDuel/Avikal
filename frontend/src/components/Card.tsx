import React, { forwardRef } from 'react'
import { motion, type HTMLMotionProps } from 'framer-motion'
import { cn } from '../lib/utils'

interface CardProps extends Omit<HTMLMotionProps<'div'>, 'ref'> {
  glass?: boolean
  hover?: boolean
}

const Card = forwardRef<HTMLDivElement, CardProps>(
  ({ className, glass, hover = true, children, ...props }, ref) => {
    return (
      <motion.div
        ref={ref}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.4, 0, 0.2, 1] }}
        whileHover={hover ? { y: -2, transition: { duration: 0.2 } } : {}}
        className={cn(
          glass ? 'glass' : 'card',
          'relative overflow-hidden group',
          className
        )}
        {...props}
      >
        {/* Subtle gradient overlay on hover */}
        {hover && (
          <div className="absolute inset-0 bg-gradient-to-br from-primary-500/0 via-transparent to-transparent group-hover:from-primary-500/5 transition-all duration-500 pointer-events-none" />
        )}
        
        <div className="relative z-10">
          {children as React.ReactNode}
        </div>
      </motion.div>
    )
  }
)

Card.displayName = 'Card'

export default Card

