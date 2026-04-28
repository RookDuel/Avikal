import { Component, type ErrorInfo, type ReactNode } from 'react'
import { logger } from '../lib/logger'
import { parseError } from '../lib/errors'
import { ErrorMessage } from './ErrorMessage'

interface Props {
  children: ReactNode
  /** Optional fallback UI. Receives the error and a reset callback. */
  fallback?: (error: Error, reset: () => void) => ReactNode
  /** Optional context label for logging (e.g. "Encrypt page") */
  context?: string
}

interface State {
  hasError: boolean
  error: Error | null
}

/**
 * React error boundary that catches unhandled component errors,
 * logs them with timestamp and context, and renders a graceful fallback UI.
 *
 * Requirement 7.4 – catch and handle all JavaScript frontend errors
 * Requirement 7.5 – implement error boundaries in React components
 * Requirement 7.6 – log all errors to file for debugging purposes
 */
export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    logger.error(
      `Unhandled React error: ${error.message}`,
      this.props.context ?? 'ErrorBoundary',
      {
        stack: error.stack,
        componentStack: info.componentStack,
      }
    )
  }

  private reset = (): void => {
    this.setState({ hasError: false, error: null })
  }

  render(): ReactNode {
    if (this.state.hasError && this.state.error) {
      if (this.props.fallback) {
        return this.props.fallback(this.state.error, this.reset)
      }

      const appError = parseError(this.state.error)

      return (
        <div className="flex flex-col items-center justify-center min-h-[300px] p-8">
          <div className="w-full max-w-md">
            <ErrorMessage
              error={appError}
              onRetry={this.reset}
            />
            <p className="mt-3 text-xs text-av-muted text-center">
              The error has been logged. Please try again or restart the application.
            </p>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary
