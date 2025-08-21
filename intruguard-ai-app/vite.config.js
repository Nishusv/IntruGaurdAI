import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  // Add this base property:
  base: "/IntruGaurdAI/", // IMPORTANT: Replace 'intruguard-ai-app' with your actual GitHub repository name
})