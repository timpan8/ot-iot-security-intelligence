import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath, URL } from 'node:url';

// Bas-sökväg för GitHub Pages (https://<owner>.github.io/<repo>/).
// Sätt VITE_BASE_PATH="/" för lokal utveckling på rot eller egen domän.
const base = process.env.VITE_BASE_PATH ?? '/ot-iot-security-intelligence/';

export default defineConfig({
  base,
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
      '@schemas': fileURLToPath(new URL('./schemas', import.meta.url)),
    },
  },
  build: {
    sourcemap: false,
    // CSP tillåter inte data:-typsnitt (font-src 'self') – inline aldrig tillgångar
    assetsInlineLimit: 0,
    target: 'es2022',
  },
});
