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
    },
  },
})

const app = createApp(App)

app.use(PrimeVue, {
  theme: {
    preset: CyberShieldPreset,
    options: {
      darkModeSelector: false,
    },
  },
})

app.use(ToastService)
app.directive('tooltip', Tooltip)
app.mount('#app')
