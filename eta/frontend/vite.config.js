import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import compress from 'vite-plugin-compression'

export default defineConfig({
  plugins: [
    react(),
    // Enable gzip compression
    compress({
      algorithm: 'gzip',
      ext: '.gz',
    }),
    compress({
      algorithm: 'brotliCompress',
      ext: '.br',
    }),
  ],
  server: {
    host: '0.0.0.0',
    port: 3000,
    strictPort: false,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        cookieDomainRewrite: 'localhost',
        ws: true,
      }
    }
  },
  build: {
    // ESNext for smaller bundles
    target: 'esnext',
    // Use esbuild (built-in with Vite 5+)
    minify: 'esbuild',
    rollupOptions: {
      output: {
        // Content hash for cache busting
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
        manualChunks: (id) => {
          // Split vendor chunks for better caching
          if (id.includes('node_modules')) {
            if (id.includes('recharts')) {
              return 'vendor-charts'
            }
            if (id.includes('react-router')) {
              return 'vendor-router'
            }
            if (id.includes('axios')) {
              return 'vendor-http'
            }
            return 'vendor'
          }
        }
      }
    },
    // Enable CSS code splitting
    cssCodeSplit: true,
    // Source maps for production (disable for smaller builds)
    sourcemap: false,
    // Chunk size warning limit
    chunkSizeWarningLimit: 500
  },
  optimizeDeps: {
    include: ['react', 'react-dom', 'react-router-dom', 'recharts']
  },
  // Cache optimization
  cacheDir: 'node_modules/.vite'
})