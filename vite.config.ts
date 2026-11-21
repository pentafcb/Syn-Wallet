import { defineConfig } from 'vite';
import path from 'path';
export default defineConfig({
  root: 'client',
  publicDir: false,
  // assetsInlineLimit 0: never inline fonts/assets as data: URIs — the strict
  // CSP (font-src 'self') refuses data: fonts. Everything ships as real files.
  build: { outDir: '../public', emptyOutDir: false, target: 'es2022', sourcemap: false, assetsInlineLimit: 0 },
  resolve: { alias: { '@wallet': path.resolve(__dirname, 'client/lib') } },
});
