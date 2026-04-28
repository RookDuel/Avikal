import { useState } from 'react'
import { motion } from 'framer-motion'
import { Shield } from 'lucide-react'
import Button from './Button'
import AuthModal from './AuthModal'

interface AuthGateProps {
  message?: string
  onLogin?: () => void
}

export default function AuthGate({
  message = 'Aavrit connection required to access private Aavrit time-capsule features',
  onLogin,
}: AuthGateProps) {
  const [showAuthModal, setShowAuthModal] = useState(false)

  const handleLogin = () => {
    if (onLogin) {
      onLogin()
    } else {
      setShowAuthModal(true)
    }
  }

  return (
    <>
      <div className="max-w-4xl mx-auto p-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center space-y-6"
        >
          <div className="w-20 h-20 mx-auto rounded-2xl bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center shadow-lg shadow-orange-500/20">
            <Shield className="w-10 h-10 text-white" />
          </div>

          <div className="space-y-3">
            <h1 className="text-3xl font-bold text-av-main">Aavrit Connection Required</h1>
            <p className="text-av-muted max-w-md mx-auto">{message}</p>
          </div>

          <Button onClick={handleLogin}>
            <Shield className="w-4 h-4" />
            Connect Aavrit
          </Button>
        </motion.div>
      </div>

      <AuthModal isOpen={showAuthModal} onClose={() => setShowAuthModal(false)} />
    </>
  )
}
