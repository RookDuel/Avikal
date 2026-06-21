/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AVIKAL_RELEASE_CHANNEL?: 'beta' | 'production'
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
