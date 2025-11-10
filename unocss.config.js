// unocss.config.js (Kadam 19 Update)
import { defineConfig, presetUno } from 'unocss'

export default defineConfig({
  presets: [
    presetUno({
      // NAYA: Dark mode ko chalu karna
      dark: 'class', 
    }),
  ],
  content: {
    filesystem: [
      './public/**/*.html',
    ],
  },
})
