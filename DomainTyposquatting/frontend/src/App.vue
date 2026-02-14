<template>
  <div class="app-container">
    <header class="app-header">
      <div class="header-left">
        <i class="pi pi-shield" style="font-size: 1.4rem; color: #00d4ff"></i>
        <h1>{{ isConfigRoute ? 'Configuration' : 'Typosquatting Dashboard' }}</h1>
        <span class="brand">Wizard Cyber</span>
      </div>
      <div style="display: flex; align-items: center; gap: 1rem">
        <a
          v-if="customers.length && isConfigRoute"
          :href="'/?customers=' + customers.join(',')"
          style="color: #8892b0; font-size: 0.85rem; text-decoration: none"
        >
          <i class="pi pi-arrow-left" style="margin-right: 0.3rem"></i>Dashboard
        </a>
        <a
          v-if="customers.length && !isConfigRoute"
          :href="'/config?customers=' + customers.join(',')"
          style="color: #8892b0; font-size: 0.85rem; text-decoration: none"
        >
          <i class="pi pi-cog" style="margin-right: 0.3rem"></i>Configure
        </a>
      </div>
    </header>

    <main class="app-main">
      <div v-if="!customers.length" style="text-align: center; padding: 4rem 1rem; color: #8892b0">
        <i class="pi pi-info-circle" style="font-size: 2rem; display: block; margin-bottom: 1rem"></i>
        <p>Add <code>?customers=Name</code> to the URL to load.</p>
      </div>
      <ConfigPage  v-else-if="isConfigRoute" :customers="customers" />
      <DomainDashboard v-else :customers="customers" />
    </main>

    <Toast position="bottom-right" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import Toast from 'primevue/toast'
import DomainDashboard from './components/DomainDashboard.vue'
import ConfigPage from './components/ConfigPage.vue'

const customers = ref<string[]>([])
const isConfigRoute = ref(false)

onMounted(() => {
  const params = new URLSearchParams(window.location.search)
  const raw = params.get('customers')
  if (raw) {
    customers.value = raw.split(',').map(s => s.trim()).filter(Boolean)
  }
  isConfigRoute.value = window.location.pathname === '/config'
})
</script>
