import { useState, useMemo } from 'react'
import { ChevronRight, ChevronDown, FileText, Folder, FolderOpen, X } from 'lucide-react'

// ── Types ────────────────────────────────────────────────────
export interface FileNode {
  name: string
  path: string
  isDir: boolean
  size: number
  children?: FileNode[]
  error?: boolean
}

function formatSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), units.length - 1)
  return `${(bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

function countFiles(node: FileNode): number {
  if (!node.isDir) return 1
  return (node.children || []).reduce((sum, c) => sum + countFiles(c), 0)
}

// ── Single Tree Node ────────────────────────────────────────
function TreeNode({ node, depth, searchQuery }: { node: FileNode; depth: number; searchQuery: string }) {
  const [expanded, setExpanded] = useState(depth < 1)

  const matchesSearch = !searchQuery || node.name.toLowerCase().includes(searchQuery.toLowerCase())
  const childrenMatchSearch = searchQuery && node.isDir && node.children?.some(c =>
    c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (c.isDir && c.children?.some(gc => gc.name.toLowerCase().includes(searchQuery.toLowerCase())))
  )

  if (searchQuery && !matchesSearch && !childrenMatchSearch) return null

  const isExpandedOrForced = expanded || (!!searchQuery && !!childrenMatchSearch)

  return (
    <div>
      <div
        className={`flex items-center gap-1.5 py-[5px] pr-3 rounded-md cursor-default transition-colors duration-150 group
          ${node.isDir ? 'hover:bg-av-border/10 dark:hover:bg-white/[0.04]' : 'hover:bg-av-border/10 dark:hover:bg-white/[0.03]'}
          ${matchesSearch && searchQuery ? 'bg-av-accent/5' : ''}`}
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
        onClick={() => node.isDir && setExpanded(e => !e)}
      >
        {/* Expand/Collapse toggle */}
        {node.isDir ? (
          <button className="w-4 h-4 flex items-center justify-center shrink-0 text-av-muted/60 hover:text-av-main transition-colors">
            {isExpandedOrForced
              ? <ChevronDown className="w-3.5 h-3.5" />
              : <ChevronRight className="w-3.5 h-3.5" />}
          </button>
        ) : (
          <span className="w-4 h-4 shrink-0" />
        )}

        {/* Icon */}
        {node.isDir ? (
          isExpandedOrForced
            ? <FolderOpen className="w-4 h-4 text-amber-400 shrink-0" strokeWidth={1.5} />
            : <Folder className="w-4 h-4 text-amber-400/70 shrink-0" strokeWidth={1.5} />
        ) : (
          <FileText className="w-4 h-4 text-av-muted/70 shrink-0" strokeWidth={1.5} />
        )}

        {/* Name */}
        <span className={`text-[12.5px] truncate ${node.isDir ? 'text-av-main font-medium' : 'text-av-muted font-normal'}`}>
          {node.name}
        </span>

        {/* Meta */}
        <span className="ml-auto text-[10px] text-av-muted/50 font-mono shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
          {node.isDir ? `${countFiles(node)} files` : formatSize(node.size)}
        </span>
      </div>

      {/* Children */}
      {node.isDir && isExpandedOrForced && node.children && (
        <div className="relative">
          {depth < 6 && (
            <div
              className="absolute top-0 bottom-0 border-l border-av-border/25 dark:border-white/[0.06]"
              style={{ left: `${depth * 16 + 16}px` }}
            />
          )}
          {node.children.map(child => (
            <TreeNode key={child.path} node={child} depth={depth + 1} searchQuery={searchQuery} />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Top-Level Entry (removable) ────────────────────────────
function TopLevelEntry({
  node,
  searchQuery,
  onRemove
}: {
  node: FileNode
  searchQuery: string
  onRemove: () => void
}) {
  const [expanded, setExpanded] = useState(true)
  const fileCount = countFiles(node)

  return (
    <div className="mb-1">
      {/* Root header */}
      <div
        className="flex items-center gap-2 py-2 px-3 rounded-lg bg-av-border/10 dark:bg-white/[0.02] hover:bg-av-border/15 dark:hover:bg-white/[0.04] transition-colors border border-av-border/25 dark:border-white/[0.04] group cursor-default"
        onClick={() => node.isDir && setExpanded(e => !e)}
      >
        {node.isDir ? (
          <button className="w-4 h-4 flex items-center justify-center shrink-0 text-av-muted/60">
            {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          </button>
        ) : (
          <span className="w-4 h-4 shrink-0" />
        )}

        {node.isDir
          ? (expanded
              ? <FolderOpen className="w-[15px] h-[15px] text-amber-400 shrink-0" strokeWidth={1.5} />
              : <Folder className="w-[15px] h-[15px] text-amber-400/70 shrink-0" strokeWidth={1.5} />)
          : <FileText className="w-[15px] h-[15px] text-av-muted/70 shrink-0" strokeWidth={1.5} />
        }

        <span className="text-[13px] text-av-main font-semibold truncate">{node.name}</span>

        <span className="ml-auto flex items-center gap-3 shrink-0">
          <span className="text-[10px] text-av-muted/50 font-mono">
            {node.isDir ? `${fileCount} file${fileCount !== 1 ? 's' : ''} · ${formatSize(node.size)}` : formatSize(node.size)}
          </span>
          <button
            onClick={e => { e.stopPropagation(); onRemove() }}
            className="w-6 h-6 rounded-md flex items-center justify-center text-red-500/60 hover:text-red-400 hover:bg-red-500/10 opacity-0 group-hover:opacity-100 transition-all"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </span>
      </div>

      {/* Children tree */}
      {node.isDir && expanded && node.children && (
        <div className="ml-2">
          {node.children.map(child => (
            <TreeNode key={child.path} node={child} depth={1} searchQuery={searchQuery} />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main Component ─────────────────────────────────────────
export default function FileTree({
  nodes,
  searchQuery,
  onRemoveRoot
}: {
  nodes: FileNode[]
  searchQuery: string
  onRemoveRoot: (rootPath: string) => void
}) {
  const totalFiles = useMemo(() => nodes.reduce((s, n) => s + countFiles(n), 0), [nodes])
  const totalSize = useMemo(() => nodes.reduce((s, n) => s + (n.size || 0), 0), [nodes])

  return (
    <div className="flex flex-col h-full">
      {/* Summary bar */}
      <div className="px-4 py-2 flex items-center gap-4 border-b border-av-border/25 dark:border-white/[0.04] bg-av-border/10 dark:bg-white/[0.01] shrink-0">
        <span className="text-[10px] text-av-muted/60 font-mono uppercase tracking-wider">
          {nodes.length} root{nodes.length !== 1 ? 's' : ''} · {totalFiles} file{totalFiles !== 1 ? 's' : ''} · {formatSize(totalSize)}
        </span>
      </div>

      {/* Tree */}
      <div className="flex-1 overflow-y-auto custom-scrollbar px-3 py-3 space-y-1">
        {nodes.map(node => (
          <TopLevelEntry
            key={node.path}
            node={node}
            searchQuery={searchQuery}
            onRemove={() => onRemoveRoot(node.path)}
          />
        ))}
      </div>
    </div>
  )
}
