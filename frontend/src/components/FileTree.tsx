import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronDown, ChevronRight, FileText, Folder, FolderOpen, Trash2, X } from 'lucide-react'
import { cn } from '../lib/utils'

export interface FileNode {
  name: string
  path: string
  isDir: boolean
  size: number
  children?: FileNode[]
  error?: boolean
}

type SelectionState = 'checked' | 'unchecked' | 'mixed'

function formatSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), units.length - 1)
  return `${(bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

function countFiles(node: FileNode): number {
  if (!node.isDir) return 1
  return (node.children || []).reduce((sum, child) => sum + countFiles(child), 0)
}

export function collectDescendantPaths(node: FileNode): string[] {
  const paths = [node.path]
  for (const child of node.children || []) {
    paths.push(...collectDescendantPaths(child))
  }
  return paths
}

function flattenPaths(nodes: FileNode[]): string[] {
  return nodes.flatMap((node) => collectDescendantPaths(node))
}

function hasMatchingDescendant(node: FileNode, query: string): boolean {
  if (!node.isDir || !node.children) return false
  return node.children.some((child) =>
    child.name.toLowerCase().includes(query)
    || child.path.toLowerCase().includes(query)
    || hasMatchingDescendant(child, query),
  )
}

function isNodeVisible(node: FileNode, query: string): boolean {
  if (!query) return true
  return node.name.toLowerCase().includes(query)
    || node.path.toLowerCase().includes(query)
    || hasMatchingDescendant(node, query)
}

export function countVisibleMatches(nodes: FileNode[], searchQuery: string): number {
  const query = searchQuery.trim().toLowerCase()
  if (!query) return nodes.length
  let count = 0
  const visit = (node: FileNode) => {
    if (node.name.toLowerCase().includes(query) || node.path.toLowerCase().includes(query)) {
      count += 1
    }
    for (const child of node.children || []) visit(child)
  }
  nodes.forEach(visit)
  return count
}

export function getSelectionState(node: FileNode, selectedPaths: Set<string>): SelectionState {
  const paths = collectDescendantPaths(node)
  const selectedCount = paths.filter((path) => selectedPaths.has(path)).length
  if (selectedCount === 0) return 'unchecked'
  if (selectedCount === paths.length) return 'checked'
  return 'mixed'
}

export function pruneTreeByPaths(nodes: FileNode[], pathsToRemove: Set<string>): FileNode[] {
  return nodes
    .filter((node) => !pathsToRemove.has(node.path))
    .map((node) => {
      const children = node.children ? pruneTreeByPaths(node.children, pathsToRemove) : undefined
      return {
        ...node,
        children,
        size: node.isDir && children ? children.reduce((sum, child) => sum + (child.size || 0), 0) : node.size,
      }
    })
}

function SelectionBox({
  state,
  onChange,
  label,
}: {
  state: SelectionState
  onChange: () => void
  label: string
}) {
  const ref = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (ref.current) ref.current.indeterminate = state === 'mixed'
  }, [state])

  return (
    <input
      ref={ref}
      type="checkbox"
      checked={state === 'checked'}
      onChange={onChange}
      aria-label={label}
      className="h-3.5 w-3.5 shrink-0 rounded border-av-border/70 bg-av-surface/60 accent-av-main"
      onClick={(event) => event.stopPropagation()}
    />
  )
}

function TreeRow({
  node,
  depth,
  searchQuery,
  selectedPaths,
  onSelectionChange,
  onRemovePaths,
}: {
  node: FileNode
  depth: number
  searchQuery: string
  selectedPaths: Set<string>
  onSelectionChange: (paths: string[], selected: boolean) => void
  onRemovePaths: (paths: string[]) => void
}) {
  const [expanded, setExpanded] = useState(depth < 1)
  const query = searchQuery.trim().toLowerCase()
  const matchesSelf = !query || node.name.toLowerCase().includes(query) || node.path.toLowerCase().includes(query)
  const hasVisibleChild = Boolean(query && hasMatchingDescendant(node, query))

  if (!matchesSelf && !hasVisibleChild) return null

  const forcedExpanded = Boolean(query && hasVisibleChild)
  const isExpanded = expanded || forcedExpanded
  const selectionState = getSelectionState(node, selectedPaths)
  const descendantPaths = collectDescendantPaths(node)
  const meta = node.isDir
    ? `${countFiles(node)} file${countFiles(node) !== 1 ? 's' : ''} - ${formatSize(node.size)}`
    : formatSize(node.size)

  return (
    <div>
      <div
        className={cn(
          'group grid min-w-0 grid-cols-[auto_auto_auto_1fr_auto_auto] items-center gap-2 rounded-lg px-2 py-1.5 text-left transition-colors',
          node.isDir ? 'cursor-pointer hover:bg-av-border/12' : 'hover:bg-av-border/8',
          matchesSelf && query ? 'bg-av-border/16 ring-1 ring-av-border/45' : '',
        )}
        style={{ paddingLeft: `${depth * 14 + 8}px` }}
        onClick={() => node.isDir && setExpanded((value) => !value)}
      >
        <SelectionBox
          state={selectionState}
          label={`Select ${node.name}`}
          onChange={() => onSelectionChange(descendantPaths, selectionState !== 'checked')}
        />

        {node.isDir ? (
          <button
            className="flex h-5 w-5 items-center justify-center rounded-md text-av-muted/70 transition-colors hover:text-av-main"
            type="button"
            onClick={(event) => { event.stopPropagation(); setExpanded((value) => !value) }}
          >
            {isExpanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          </button>
        ) : (
          <span className="h-5 w-5" />
        )}

        {node.isDir ? (
          isExpanded
            ? <FolderOpen className="h-4 w-4 text-av-muted" strokeWidth={1.5} />
            : <Folder className="h-4 w-4 text-av-muted" strokeWidth={1.5} />
        ) : (
          <FileText className="h-4 w-4 text-av-muted/80" strokeWidth={1.5} />
        )}

        <div className="min-w-0">
          <p className={cn('truncate text-[12.5px]', node.isDir ? 'font-semibold text-av-main' : 'font-medium text-av-muted')}>
            {node.name}
          </p>
          {depth === 0 && (
            <p className="truncate font-mono text-[10px] text-av-muted/55">{node.path}</p>
          )}
        </div>

        <span className="hidden shrink-0 font-mono text-[10px] text-av-muted/55 sm:block">
          {meta}
        </span>

        <button
          type="button"
          onClick={(event) => { event.stopPropagation(); onRemovePaths(descendantPaths) }}
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-red-400/60 opacity-80 transition-colors hover:bg-red-500/10 hover:text-red-400 sm:opacity-0 sm:group-hover:opacity-100"
          title={`Remove ${node.name}`}
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      {node.isDir && isExpanded && node.children && (
        <div>
          {node.children.map((child) => (
            <TreeRow
              key={child.path}
              node={child}
              depth={depth + 1}
              searchQuery={searchQuery}
              selectedPaths={selectedPaths}
              onSelectionChange={onSelectionChange}
              onRemovePaths={onRemovePaths}
            />
          ))}
        </div>
      )}
    </div>
  )
}

export default function FileTree({
  nodes,
  searchQuery,
  selectedPaths,
  onSelectionChange,
  onRemovePaths,
  onClearAll,
}: {
  nodes: FileNode[]
  searchQuery: string
  selectedPaths: Set<string>
  onSelectionChange: (paths: string[], selected: boolean) => void
  onRemovePaths: (paths: string[]) => void
  onClearAll: () => void
}) {
  const totalFiles = useMemo(() => nodes.reduce((sum, node) => sum + countFiles(node), 0), [nodes])
  const totalSize = useMemo(() => nodes.reduce((sum, node) => sum + (node.size || 0), 0), [nodes])
  const selectedCount = selectedPaths.size
  const visibleMatches = countVisibleMatches(nodes, searchQuery)
  const allPaths = useMemo(() => flattenPaths(nodes), [nodes])
  const allSelectionState: SelectionState = selectedCount === 0
    ? 'unchecked'
    : selectedCount >= allPaths.length
      ? 'checked'
      : 'mixed'

  return (
    <div className="av-tree-surface flex h-full flex-col">
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-av-border/40 px-4 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <SelectionBox
            state={allSelectionState}
            label="Select all staged files"
            onChange={() => onSelectionChange(allPaths, allSelectionState !== 'checked')}
          />
          <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-av-muted">
            {nodes.length} root{nodes.length !== 1 ? 's' : ''} - {totalFiles} file{totalFiles !== 1 ? 's' : ''} - {formatSize(totalSize)}
          </span>
          {searchQuery.trim() && (
            <span className="rounded-full border border-av-border/40 px-2 py-0.5 text-[10px] text-av-muted">
              {visibleMatches} match{visibleMatches !== 1 ? 'es' : ''}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {selectedCount > 0 && (
            <button
              type="button"
              onClick={() => onRemovePaths(Array.from(selectedPaths))}
              className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/25 bg-red-500/10 px-3 py-1.5 text-[11px] font-semibold text-red-400 transition-colors hover:bg-red-500/16"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Delete Selected ({selectedCount})
            </button>
          )}
          <button
            type="button"
            onClick={onClearAll}
            className="rounded-lg border border-av-border/45 bg-av-surface/45 px-3 py-1.5 text-[11px] font-semibold text-av-muted transition-colors hover:bg-av-border/12 hover:text-av-main"
          >
            Clear All
          </button>
        </div>
      </div>

      <div className="custom-scrollbar flex-1 overflow-y-auto p-2">
        {nodes.some((node) => isNodeVisible(node, searchQuery.trim().toLowerCase())) ? (
          nodes.map((node) => (
            <TreeRow
              key={node.path}
              node={node}
              depth={0}
              searchQuery={searchQuery}
              selectedPaths={selectedPaths}
              onSelectionChange={onSelectionChange}
              onRemovePaths={onRemovePaths}
            />
          ))
        ) : (
          <div className="flex h-full min-h-48 items-center justify-center text-center">
            <div>
              <p className="text-sm font-semibold text-av-main">No files match this filter</p>
              <p className="mt-1 text-xs text-av-muted">Try a different filename or folder name.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
