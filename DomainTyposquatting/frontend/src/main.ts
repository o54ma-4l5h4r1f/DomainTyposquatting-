import { createApp } from 'vue'
import PrimeVue from 'primevue/config'
import Aura from '@primevue/themes/aura'
import { definePreset } from '@primevue/themes'
import ToastService from 'primevue/toastservice'
import Tooltip from 'primevue/tooltip'
import 'primeicons/primeicons.css'
import App from './App.vue'
import './assets/styles.css'

const CyberShieldPreset = definePreset(Aura, {
  semantic: {
    primary: {
      50: '#FFF6F7',
      100: '#FFE2E5',
      200: '#FFB9C1',
      300: '#FF909D',
      400: '#FF6779',
      500: '#FF3E55',
      600: '#FF1631',
      700: '#EC001C',
      800: '#C30017',
      900: '#8B0010',
      950: '#6F000D',
    },
    colorScheme: {
      light: {
        primary: {
          color: '#FF1631',
          contrastColor: '#ffffff',
          hoverColor: '#EC001C',
          activeColor: '#C30017',
        },
        highlight: {
          background: '#FF1631',
          focusBackground: '#EC001C',
          color: '#ffffff',
          focusColor: '#ffffff',
        },
      },
      dark: {
        primary: {
          color: '#FF6779',
          contrastColor: '#ffffff',
          hoverColor: '#FF909D',
          activeColor: '#FFB9C1',
        },
        highlight: {
          background: '#FF6779',
          focusBackground: '#FF909D',
          color: '#ffffff',
          focusColor: '#ffffff',
        },
        surface: {
          0: '#000000',
          50: '#030712',
          100: '#111827',
          200: '#1f2937',
          300: '#374151',
          400: '#4b5563',
          500: '#6b7280',
          600: '#9ca3af',
          700: '#d1d5db',
          800: '#e5e7eb',
          900: '#f3f4f6',
          950: '#f9fafb',
        },
      },
    },
  },
})

const app = createApp(App)

app.use(PrimeVue, {
  theme: {
    preset: CyberShieldPreset,
    options: {
      darkModeSelector: 'system',
    },
  },
})

app.use(ToastService)
app.directive('tooltip', Tooltip)
app.mount('#app')
