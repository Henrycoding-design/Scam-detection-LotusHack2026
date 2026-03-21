import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => ({
  base: './',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: 'scam-shield/assets',
    emptyOutDir: true,
    assetsDir: '.',
    rollupOptions: {
      input: 'dashboard.html',
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
  server: {
    hmr: process.env.DISABLE_HMR !== 'true',
  },
}));
