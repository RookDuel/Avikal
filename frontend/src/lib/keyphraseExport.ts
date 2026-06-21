import { toast } from 'sonner'

function normalizeKeyphraseText(keyphrase: string): string {
  return keyphrase.trim().split(/\s+/).filter(Boolean).join(' ')
}

export async function copyKeyphraseToClipboard(keyphrase: string): Promise<boolean> {
  const normalized = normalizeKeyphraseText(keyphrase)
  if (!normalized) return false

  try {
    await navigator.clipboard.writeText(normalized)
    return true
  } catch (error) {
    try {
      const textArea = document.createElement('textarea')
      textArea.value = normalized
      textArea.setAttribute('readonly', 'true')
      textArea.style.position = 'fixed'
      textArea.style.left = '-9999px'
      textArea.style.top = '0'
      document.body.appendChild(textArea)
      textArea.focus()
      textArea.select()
      const copied = document.execCommand('copy')
      document.body.removeChild(textArea)
      return copied
    } catch {
      console.warn('Keyphrase clipboard copy failed:', error)
      return false
    }
  }
}

export function formatStructuredKeyphrase(keyphrase: string, context: string): string {
  const words = normalizeKeyphraseText(keyphrase).split(' ').filter(Boolean)
  const lines = [
    'Avikal Structured Keyphrase',
    `Context: ${context}`,
    `Created: ${new Date().toISOString()}`,
    '',
    'Store this document offline. Anyone with this keyphrase and the required archive credentials may be able to unlock protected archives.',
    '',
    'Plain keyphrase:',
    words.join(' '),
    '',
    'Numbered words:',
    ...words.map((word, index) => `${String(index + 1).padStart(2, '0')}. ${word}`),
    '',
  ]
  return lines.join('\n')
}

export async function downloadStructuredKeyphrase(keyphrase: string, context: string): Promise<boolean> {
  const content = formatStructuredKeyphrase(keyphrase, context)
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
  const filename = `avikal-keyphrase-${timestamp}.txt`

  try {
    if (window.electron?.saveTextFile) {
      const savedPath = await window.electron.saveTextFile({
        defaultPath: filename,
        filters: [{ name: 'Text Document', extensions: ['txt'] }],
        content,
      })
      return Boolean(savedPath)
    }

    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
    return true
  } catch (error) {
    console.warn('Structured keyphrase download failed:', error)
    toast.error('Failed to save keyphrase document')
    return false
  }
}
