<template>
  <div class="app-container">
    <header class="app-header">
      <div class="header-left">
        <i class="pi pi-shield" style="font-size: 1.4rem; color: #00d4ff"></i>
        <h1>Typosquatting Dashboard</h1>
        <span class="brand">Wizard Cyber</span>
      </div>
      <div v-if="customers.length" style="color: #8892b0; font-size: 0.85rem">
        {{ customers.join(', ') }}
      </div>
    </header>

    <main class="app-main">
      <div v-if="!customers.length" style="text-align: center; padding: 4rem 1rem; color: #8892b0">
        <i class="pi pi-info-circle" style="font-size: 2rem; display: block; margin-bottom: 1rem"></i>
        <p>Add <code>?customers=Name1,Name2</code> to the URL to load the dashboard.</p>
      </div>
      <DomainDashboard v-else :customers="customers" />
    </main>

    <Toast position="bottom-right" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import Toast from 'primevue/toast'
import DomainDashboard from './components/DomainDashboard.vue'

const customers = ref<string[]>([])

onMounted(() => {
  const params = new URLSearchParams(window.location.search)
  const raw = params.get('customers')
  if (raw) {
    customers.value = raw.split(',').map(s => s.trim()).filter(Boolean)
  }
})
</script>
