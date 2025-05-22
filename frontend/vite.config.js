import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/tools/takedowniq/',
  server: {
    host: '0.0.0.0', // Allow connections from external devices
    port: 3000,      // Specify port for development server
    proxy: {
      '/tools/takedowniq/api': {
        target: 'http://69.62.66.176:8025', // Use IP address instead of localhost
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/tools\/takedowniq\/api/, '')
      }
    }
  },
  build: {
    outDir: '/var/www/html/tools/takedowniq',
    emptyOutDir: true
  }
})
