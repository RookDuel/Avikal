import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: './', // Use relative paths for Electron
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    // Keep the dev contract deterministic for Electron and wait-on.
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})
