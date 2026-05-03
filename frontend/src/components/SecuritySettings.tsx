import { useState, useEffect } from 'react'
import { Settings, X, Activity, Sun, Moon, Monitor, Download, type LucideIcon } from 'lucide-react'
import { toast } from 'sonner'
import { motion, AnimatePresence } from 'framer-motion'
import { useTheme } from '../contexts/ThemeContext'
import { fetchBackend } from '../lib/backend'
import { cn } from '../lib/utils'

interface SecuritySettingsProps {
  isOpen: boolean
  onClose: () => void
}

interface SecuritySettings {
  activity_log?: {
    entry_count: number
    storage_path: string
    last_event_at?: string | null
    export_format?: string
  }
}

type TabType = 'appearance' | 'advanced'
type ThemeOption = 'light' | 'dark' | 'system'

const THEME_OPTIONS: Array<{ id: ThemeOption; label: string; icon: LucideIcon; desc: string }> = [
  { id: 'light', label: 'Light', icon: Sun, desc: 'Soft Professional' },
  { id: 'dark', label: 'Dark', icon: Moon, desc: 'Midnight Mist' },
  { id: 'system', label: 'System', icon: Monitor, desc: 'Auto-detect' },
]

export default function SecuritySettings({ isOpen, onClose }: SecuritySettingsProps) {
  const { theme, setTheme } = useTheme()
  const [settings, setSettings] = useState<SecuritySettings | null>(null)
  const [loading, setLoading] = useState(false)
  const [exportingAuditLog, setExportingAuditLog] = useState(false)
  
  const [activeTab, setActiveTab] = useState<TabType>('appearance')

  useEffect(() => {
    if (isOpen) {
      loadSettings()
      setActiveTab('appearance')
    }
  }, [isOpen])

  const loadSettings = async () => {
    try {
      setLoading(true)
      const response = await fetchBackend('/api/security/settings')
      const data = await response.json()
      
      if (data.success) {
        setSettings(data.settings)
      }
    } catch {
      toast.error('Failed to load security settings')
    } finally {
      setLoading(false)
    }
  }

  const formatAuditTimestamp = (value?: string | null) => {
    if (!value) return 'No events yet'
    const parsed = new Date(value)
    if (Number.isNaN(parsed.getTime())) return value
    return parsed.toLocaleString()
  }

  const exportActivityLog = async () => {
    try {
      setExportingAuditLog(true)
      const response = await fetchBackend('/api/security/activity-log/export')
      const rawText = await response.text()

      let data: {
        success?: boolean
        filename?: string
        markdown?: string
        entry_count?: number
        detail?: string
        message?: string
      } = {}

      try {
        data = JSON.parse(rawText)
      } catch {
        throw new Error('Failed to parse activity log export response')
      }

      if (!response.ok || !data.success || !data.markdown) {
        throw new Error(data.detail || data.message || 'Failed to export activity audit log')
      }

      const electron = window.electron
      const filename = data.filename || 'avikal-activity-log.md'
      const entryCount = data.entry_count ?? 0

      if (electron?.saveTextFile) {
        const selectedPath = await electron.saveTextFile({
          defaultPath: filename,
          filters: [{ name: 'Markdown Files', extensions: ['md'] }],
          content: data.markdown,
        })
        if (!selectedPath) return

        toast.success(`Activity audit exported (${entryCount} entr${entryCount === 1 ? 'y' : 'ies'})`)
        return
      }

      const blob = new Blob([data.markdown], { type: 'text/markdown;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      link.click()
      URL.revokeObjectURL(url)

      toast.success(`Activity audit exported (${entryCount} entr${entryCount === 1 ? 'y' : 'ies'})`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to export activity audit log'
      toast.error(message)
    } finally {
      setExportingAuditLog(false)
    }
  }

  if (!isOpen) return null

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="theme-backdrop fixed inset-0 flex items-center justify-center z-[100] p-4 lg:p-10"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0, y: 10 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.95, opacity: 0, y: 10 }}
          className="bg-av-surface rounded-[2rem] shadow-2xl overflow-hidden flex flex-row w-full max-w-5xl h-[700px] max-h-[90vh] border border-av-border"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Left Navigation Sidebar */}
          <div className="w-72 bg-av-border/5 border-r border-av-border flex flex-col p-6 shrink-0 h-full">
            <div className="flex items-center gap-4 mb-10 pt-2 px-2">
              <div className="w-10 h-10 rounded-xl bg-av-main flex items-center justify-center shadow-md">
                <Settings className="w-5 h-5 text-av-surface" />
              </div>
              <div>
                <h2 className="text-xl font-bold tracking-tight text-av-main">Preferences</h2>
                <p className="text-xs text-av-muted">Appearance & Activity</p>
              </div>
            </div>

            <nav className="flex flex-col gap-2 relative">
              <button
                onClick={() => setActiveTab('appearance')}
                className={cn(
                  'flex items-center gap-3 px-4 py-3.5 rounded-xl transition-all font-medium text-sm',
                  activeTab === 'appearance' 
                    ? 'bg-av-surface shadow-sm border border-av-border text-av-main' 
                    : 'text-av-muted hover:bg-av-border/10 hover:text-av-main border border-transparent'
                )}
              >
                <Sun className={`w-4 h-4 ${activeTab === 'appearance' ? 'text-av-main' : ''}`} />
                Appearance
              </button>

              <button
                onClick={() => setActiveTab('advanced')}
                className={cn(
                  'flex items-center gap-3 px-4 py-3.5 rounded-xl transition-all font-medium text-sm',
                  activeTab === 'advanced' 
                    ? 'bg-av-surface shadow-sm border border-av-border text-av-main' 
                    : 'text-av-muted hover:bg-av-border/10 hover:text-av-main border border-transparent'
                )}
              >
                <Download className={`w-4 h-4 ${activeTab === 'advanced' ? 'text-av-main' : ''}`} />
                Activity & Export
              </button>
            </nav>
          </div>

          {/* Right Content Area */}
          <div className="flex-1 bg-av-surface h-full relative overflow-y-auto custom-scrollbar flex flex-col">
            {/* Close Button Header */}
            <div className="sticky top-0 right-0 z-20 flex justify-end p-6 pointer-events-none">
              <button 
                onClick={onClose} 
                className="w-10 h-10 rounded-full flex items-center justify-center bg-av-border/10 hover:bg-av-border/20 text-av-muted hover:text-av-main transition-colors pointer-events-auto shadow-sm border border-av-border"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 px-12 pb-12 w-full max-w-3xl -mt-6">
              {loading && !settings ? (
                <div className="flex flex-col items-center justify-center h-[50vh] text-center">
                  <Activity className="w-8 h-8 text-av-main animate-spin mb-4" />
                  <p className="text-av-muted">Loading system preferences...</p>
                </div>
              ) : settings ? (
                <AnimatePresence mode="wait">
                  <motion.div
                    key={activeTab}
                    initial={{ opacity: 0, y: 15 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -15 }}
                    transition={{ duration: 0.2 }}
                  >
                    {/* --- TAB: APPEARANCE --- */}
                    {activeTab === 'appearance' && (
                      <div className="space-y-8">
                        <div>
                          <h2 className="text-2xl font-bold tracking-tight text-av-main mb-2">Appearance</h2>
                          <p className="text-av-muted text-sm">Customize the interface theme to your preference.</p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          {THEME_OPTIONS.map(opt => (
                            <button
                              key={opt.id}
                              onClick={() => setTheme(opt.id)}
                              className={`text-left p-6 rounded-2xl border transition-all duration-200 flex flex-col items-start gap-3 ${
                                theme === opt.id
                                  ? 'border-av-accent bg-av-accent/5 ring-2 ring-av-accent/10'
                                  : 'border-av-border bg-av-surface hover:border-av-accent/30 hover:bg-av-border/10 text-av-muted'
                              }`}
                            >
                              <div className={cn(
                                "p-2 rounded-lg transition-colors",
                                theme === opt.id ? "bg-av-accent text-av-surface" : "bg-av-border/20 text-av-muted"
                              )}>
                                <opt.icon className="w-5 h-5" />
                              </div>
                              <div>
                                <h3 className="font-bold text-av-main">{opt.label}</h3>
                                <p className="text-xs text-av-muted">{opt.desc}</p>
                              </div>
                            </button>
                          ))}
                        </div>

                        <div className="p-6 bg-av-border/5 rounded-2xl border border-av-border">
                          <h3 className="text-sm font-bold text-av-main mb-2">Theme Preview</h3>
                          <div className="flex gap-2">
                            <div className="w-full h-8 rounded-lg bg-gradient-to-br from-[#F5F7FF] to-[#FBFBFF] border border-av-border" title="Light Theme Preview" />
                            <div className="w-full h-8 rounded-lg bg-[#000000] border border-av-border" title="Dark Theme Preview" />
                          </div>
                        </div>
                      </div>
                    )}

                    {/* --- TAB: ACTIVITY & EXPORT --- */}
                    {activeTab === 'advanced' && (
                      <div className="space-y-8">
                        <div>
                          <h2 className="text-2xl font-bold tracking-tight text-av-main mb-2">Activity & Export</h2>
                          <p className="text-av-muted text-sm">Operational audit visibility and export controls.</p>
                        </div>

                         <div className="bg-av-surface rounded-2xl border border-av-border p-6 shadow-sm">
                           <div className="flex items-center gap-4 mb-4">
                             <div className="w-12 h-12 rounded-xl border border-blue-200 bg-blue-50 flex items-center justify-center shrink-0">
                               <Download className="w-6 h-6 text-blue-600" />
                             </div>
                             <div>
                               <h3 className="font-bold text-lg text-av-main">Operational Audit Export</h3>
                               <p className="text-av-muted text-sm">Export archive-creation activity as a Markdown table without source filenames, paths, or contents.</p>
                             </div>
                           </div>

                           <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                             <div className="rounded-xl border border-av-border bg-av-border/5 p-4">
                               <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-av-muted mb-1">Entries</p>
                               <p className="text-2xl font-bold text-av-main">{settings.activity_log?.entry_count ?? 0}</p>
                             </div>
                             <div className="rounded-xl border border-av-border bg-av-border/5 p-4">
                               <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-av-muted mb-1">Last Event</p>
                               <p className="text-sm font-medium text-av-main">{formatAuditTimestamp(settings.activity_log?.last_event_at)}</p>
                             </div>
                             <div className="rounded-xl border border-av-border bg-av-border/5 p-4">
                               <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-av-muted mb-1">Format</p>
                               <p className="text-sm font-medium text-av-main uppercase">{settings.activity_log?.export_format || 'markdown'}</p>
                             </div>
                           </div>

                           <div className="mt-4 rounded-xl border border-av-border bg-av-border/5 p-4">
                             <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-av-muted mb-1">Raw Log Storage</p>
                             <p className="text-xs font-mono text-av-main break-all">{settings.activity_log?.storage_path || 'Unavailable'}</p>
                           </div>
                           
                           <div className="mt-6 flex flex-col md:flex-row gap-4 pt-4 border-t border-av-border/60">
                              <p className="text-xs text-av-muted flex-1 font-medium italic">
                                Do not delete or manually edit the raw audit log file if you want to preserve history. The export only includes action metadata and system performance snapshots.
                              </p>
                              <button
                                onClick={exportActivityLog}
                                disabled={exportingAuditLog}
                                className="px-6 py-3 rounded-xl bg-av-main text-av-surface font-bold text-sm shadow-sm hover:opacity-90 transition-colors whitespace-nowrap disabled:opacity-60 disabled:cursor-not-allowed"
                              >
                                {exportingAuditLog ? 'Exporting...' : 'Export Markdown Table'}
                              </button>
                           </div>
                         </div>

                       </div>
                     )}
                  </motion.div>
                </AnimatePresence>
              ) : (
                <div className="flex flex-col items-center justify-center h-[50vh] text-center">
                  <p className="text-av-muted mb-4">Could not retrieve system settings from background process.</p>
                    <button
                      onClick={loadSettings}
                      className="px-6 py-2.5 rounded-xl border border-av-border font-medium text-sm hover:bg-av-border/10 text-av-main transition-colors"
                    >
                    Retry Connection
                  </button>
                </div>
              )}
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}
