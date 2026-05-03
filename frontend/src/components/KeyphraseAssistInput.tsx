import { useEffect, useMemo, useRef, useState } from 'react'
import type { ClipboardEvent, FormEvent, KeyboardEvent } from 'react'
import { Check, Trash2, X } from 'lucide-react'
import type { KeyphraseWordPair } from '../lib/api'

export function splitKeyphraseWords(value: string): string[] {
  return value.normalize('NFKC').trim().split(/\s+/).filter(Boolean)
}

function normalizeRoman(value: string): string {
  return value.normalize('NFKC').trim().toLowerCase()
}

function hasBlockedKeyphraseCharacters(value: string): boolean {
  return /[^\p{L}\p{M}\s]/u.test(value)
}

interface ResolveResult {
  words: string[]
  ambiguous: Array<{ token: string; matches: KeyphraseWordPair[] }>
  invalid: string[]
}

export function resolveKeyphraseText(value: string, pairs: KeyphraseWordPair[]): ResolveResult {
  const hindiWords = new Set(pairs.map(pair => pair.hindi))
  const romanToPairs = new Map<string, KeyphraseWordPair[]>()
  for (const pair of pairs) {
    const key = normalizeRoman(pair.roman)
    romanToPairs.set(key, [...(romanToPairs.get(key) || []), pair])
  }

  const words: string[] = []
  const ambiguous: ResolveResult['ambiguous'] = []
  const invalid: string[] = []

  for (const token of splitKeyphraseWords(value)) {
    const normalized = token.normalize('NFKC')
    if (hindiWords.has(normalized)) {
      words.push(normalized)
      continue
    }

    const romanMatches = romanToPairs.get(normalizeRoman(token)) || []
    if (romanMatches.length === 1) {
      words.push(romanMatches[0].hindi)
    } else if (romanMatches.length > 1) {
      ambiguous.push({ token, matches: romanMatches })
    } else {
      invalid.push(token)
    }
  }

  return { words, ambiguous, invalid }
}

interface KeyphraseAssistInputProps {
  value: string
  onChange: (value: string) => void
  pairs: KeyphraseWordPair[]
  disabled?: boolean
  placeholder?: string
  onIssue?: (message: string) => void
  showClearButton?: boolean
  onClearAll?: () => void
}

export default function KeyphraseAssistInput({
  value,
  onChange,
  pairs,
  disabled = false,
  placeholder = 'Type romanized Hindi, then choose a word',
  onIssue,
  showClearButton = false,
  onClearAll,
}: KeyphraseAssistInputProps) {
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement | null>(null)
  const lastBlockedNoticeRef = useRef<{ value: string; at: number }>({ value: '', at: 0 })
  const words = splitKeyphraseWords(value)
  const queryText = query.normalize('NFKC').trim()

  const announceBlockedCharacters = (fragment: string) => {
    const nextValue = fragment.trim() || 'invalid characters'
    const now = Date.now()
    if (
      lastBlockedNoticeRef.current.value === nextValue &&
      now - lastBlockedNoticeRef.current.at < 1200
    ) {
      return
    }
    lastBlockedNoticeRef.current = { value: nextValue, at: now }
    onIssue?.('Only Hindi or romanized Hindi letters and spaces are allowed in the keyphrase field.')
  }

  const suggestions = useMemo(() => {
    if (!queryText || pairs.length === 0) return []
    const romanQuery = normalizeRoman(queryText)
    const hindiQuery = queryText

    return pairs
      .filter(pair => pair.roman.startsWith(romanQuery) || pair.hindi.startsWith(hindiQuery))
      .sort((a, b) => {
        const aExact = a.roman === romanQuery || a.hindi === hindiQuery
        const bExact = b.roman === romanQuery || b.hindi === hindiQuery
        if (aExact !== bExact) return aExact ? -1 : 1
        return a.index - b.index
      })
      .slice(0, 8)
  }, [pairs, queryText])

  useEffect(() => {
    setActiveIndex(0)
  }, [queryText])

  useEffect(() => {
    if (activeIndex >= suggestions.length) {
      setActiveIndex(Math.max(0, suggestions.length - 1))
    }
  }, [activeIndex, suggestions.length])

  const commitWords = (nextWords: string[]) => {
    onChange(nextWords.slice(0, 21).join(' '))
  }

  const addWord = (word: string) => {
    if (words.length >= 21) return
    commitWords([...words, word])
    setQuery('')
  }

  const removeWord = (index: number) => {
    commitWords(words.filter((_, wordIndex) => wordIndex !== index))
  }

  const handlePaste = (event: ClipboardEvent<HTMLInputElement>) => {
    const text = event.clipboardData.getData('text')
    if (!text.trim()) return
    if (hasBlockedKeyphraseCharacters(text)) {
      event.preventDefault()
      announceBlockedCharacters(text)
      return
    }

    const resolved = resolveKeyphraseText(text, pairs)
    if (resolved.ambiguous.length || resolved.invalid.length) {
      event.preventDefault()
      const firstAmbiguous = resolved.ambiguous[0]?.token
      const firstInvalid = resolved.invalid[0]
      onIssue?.(
        firstAmbiguous
          ? `Choose the Hindi word for "${firstAmbiguous}" from the suggestions.`
          : `No keyphrase word found for "${firstInvalid}".`,
      )
      setQuery(firstAmbiguous || firstInvalid || '')
      if (resolved.words.length) commitWords([...words, ...resolved.words])
      return
    }

    if (resolved.words.length) {
      event.preventDefault()
      commitWords([...words, ...resolved.words])
      setQuery('')
    }
  }

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Backspace' && !query && words.length > 0) {
      event.preventDefault()
      removeWord(words.length - 1)
      return
    }

    if (event.key === 'Escape' && query) {
      event.preventDefault()
      setQuery('')
      return
    }

    if (suggestions.length > 0 && (event.key === 'ArrowDown' || event.key === 'ArrowUp')) {
      event.preventDefault()
      setActiveIndex(current => {
        const direction = event.key === 'ArrowDown' ? 1 : -1
        return (current + direction + suggestions.length) % suggestions.length
      })
      return
    }

    if (suggestions.length > 0 && event.key === 'Home') {
      event.preventDefault()
      setActiveIndex(0)
      return
    }

    if (suggestions.length > 0 && event.key === 'End') {
      event.preventDefault()
      setActiveIndex(suggestions.length - 1)
      return
    }

    if (event.key === 'Enter' && suggestions.length > 0) {
      event.preventDefault()
      addWord(suggestions[activeIndex]?.hindi || suggestions[0].hindi)
    }
  }

  const handleBeforeInput = (event: FormEvent<HTMLInputElement> & { nativeEvent: InputEvent }) => {
    const fragment = event.nativeEvent.data
    if (!fragment || !hasBlockedKeyphraseCharacters(fragment)) {
      return
    }
    event.preventDefault()
    announceBlockedCharacters(fragment)
  }

  const handleQueryChange = (nextValue: string) => {
    if (!nextValue) {
      setQuery('')
      return
    }

    if (hasBlockedKeyphraseCharacters(nextValue)) {
      announceBlockedCharacters(nextValue)
      return
    }

    setQuery(nextValue)
  }

  return (
    <div
      className="overflow-hidden rounded-xl bg-container-bg border border-av-border/30 shadow-[inset_0_4px_15px_var(--container-bg)] transition-all duration-300 backdrop-blur-md focus-within:border-purple-500/45 focus-within:ring-1 focus-within:ring-purple-500/25"
      onClick={() => inputRef.current?.focus()}
    >
      <div className="flex flex-wrap gap-2 p-3 min-h-[100px] content-start">
        {words.map((word, index) => (
          <span
            key={`${word}-${index}`}
            className="inline-flex h-8 max-w-full items-center gap-1.5 rounded-lg border border-purple-500/25 bg-purple-500/10 px-2.5 text-xs font-semibold text-av-main shadow-sm transition-colors hover:border-purple-500/40 hover:bg-purple-500/15"
          >
            <span className="text-[10px] text-av-muted tabular-nums">{String(index + 1).padStart(2, '0')}</span>
            <span className="truncate">{word}</span>
            <button
              type="button"
              onClick={() => removeWord(index)}
              disabled={disabled}
              className="rounded-md p-0.5 text-av-muted transition-colors hover:bg-purple-500/15 hover:text-purple-500 disabled:opacity-40"
              title="Remove word"
            >
              <X className="h-3 w-3" />
            </button>
          </span>
        ))}

        {showClearButton && words.length > 0 && (
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation()
              onClearAll?.()
              inputRef.current?.focus()
            }}
            disabled={disabled}
            className="ml-auto inline-flex h-8 items-center gap-1.5 rounded-lg border border-av-border/40 bg-av-border/10 px-2.5 text-[11px] font-semibold text-av-muted transition-colors hover:border-red-500/25 hover:bg-red-500/10 hover:text-red-500 disabled:opacity-40"
            title="Clear keyphrase"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Clear
          </button>
        )}

        {words.length < 21 && (
          <input
            ref={inputRef}
            value={query}
            disabled={disabled}
            onBeforeInput={handleBeforeInput}
            onChange={event => handleQueryChange(event.target.value)}
            onKeyDown={handleKeyDown}
            onPaste={handlePaste}
            placeholder={words.length ? '' : placeholder}
            aria-activedescendant={suggestions[activeIndex] ? `keyphrase-suggestion-${suggestions[activeIndex].index}` : undefined}
            aria-autocomplete="list"
            aria-expanded={suggestions.length > 0}
            className="h-8 min-w-[220px] flex-1 bg-transparent text-sm font-medium text-av-main placeholder:text-av-muted placeholder:font-light focus:outline-none disabled:opacity-60"
          />
        )}
      </div>

      {suggestions.length > 0 && words.length < 21 && (
        <div className="border-t border-av-border/20 p-2">
          <div className="grid gap-1 sm:grid-cols-2" role="listbox">
            {suggestions.map((pair, index) => {
              const active = index === activeIndex
              return (
              <button
                type="button"
                id={`keyphrase-suggestion-${pair.index}`}
                key={`${pair.index}-${pair.hindi}`}
                onClick={() => addWord(pair.hindi)}
                onMouseEnter={() => setActiveIndex(index)}
                role="option"
                aria-selected={active}
                className={`flex h-9 items-center justify-between rounded-lg px-2.5 text-left text-xs transition-colors ${
                  active ? 'bg-purple-500/15 text-av-main ring-1 ring-purple-500/20' : 'hover:bg-purple-500/10'
                }`}
              >
                <span className="flex min-w-0 items-center gap-2">
                  <span className="truncate font-semibold text-av-main">{pair.hindi}</span>
                  <span className="truncate text-av-muted">{pair.roman}</span>
                </span>
                <Check className="h-3.5 w-3.5 shrink-0 text-purple-500" />
              </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
