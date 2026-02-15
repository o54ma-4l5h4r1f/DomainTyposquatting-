<template>
  <Dialog
    :visible="visible"
    @update:visible="$emit('update:visible', $event)"
    header="Configuration"
    :modal="true"
    :style="{ width: '40rem' }"
    :dismissableMask="true"
  >
    <!-- Customer selector when multiple customers -->
    <div v-if="customers.length > 1" style="margin-bottom: 1.25rem">
      <SelectButton
        v-model="activeCustomer"
        :options="customers"
        @change="loadConfig"
      />
    </div>

    <!-- Tier badge -->
    <div v-if="config" style="margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.75rem">
      <span
        class="tier-badge"
        :class="config.customer.tier === 'premium' ? 'tier-premium' : 'tier-standard'"
      >
        {{ config.customer.tier }}
      </span>
      <span style="color: var(--p-text-muted-color); font-size: 0.85rem">{{ activeCustomer }}</span>
    </div>

    <div v-if="configLoading" style="text-align: center; padding: 2rem">
      <i class="pi pi-spin pi-spinner" style="font-size: 1.5rem"></i>
    </div>

    <div v-else-if="configError" style="text-align: center; padding: 2rem; color: #f87171">
      {{ configError }}
    </div>

    <div v-else-if="config" class="config-sections">
      <!-- Keywords section -->
      <div class="config-card">
        <div class="config-section-label">Keywords</div>
        <div class="config-add">
          <InputText
            v-model="newKeyword"
            placeholder="Add keyword..."
            @keyup.enter="doAddKeyword"
            size="small"
          />
          <Button
            icon="pi pi-plus"
            severity="primary"
            size="small"
            @click="doAddKeyword"
            :disabled="!newKeyword.trim()"
          />
        </div>
        <div v-if="!config.keywords.length" style="color: var(--p-text-muted-color); font-size: 0.85rem; padding: 0.5rem 0">
          No keywords configured.
        </div>
        <div v-for="kw in config.keywords" :key="kw" class="config-item">
          <span>{{ kw }}</span>
          <Button
            icon="pi pi-trash"
            severity="danger"
            size="small"
            text
            rounded
            @click="doRemoveKeyword(kw)"
          />
        </div>
      </div>

      <!-- Monitored domains section -->
      <div class="config-card">
        <div class="config-section-label">Monitored Domains</div>
        <div class="config-add">
          <InputText
            v-model="newDomain"
            placeholder="Add domain (e.g. example.com)..."
            @keyup.enter="doAddDomain"
            size="small"
          />
          <Button
            icon="pi pi-plus"
            severity="primary"
            size="small"
            @click="doAddDomain"
            :disabled="!newDomain.trim()"
          />
        </div>
        <div v-if="!config.domains.length" style="color: var(--p-text-muted-color); font-size: 0.85rem; padding: 0.5rem 0">
          No monitored domains configured.
        </div>
        <div v-for="d in config.domains" :key="d" class="config-item">
          <span>{{ d }}</span>
          <Button
            icon="pi pi-trash"
            severity="danger"
            size="small"
            text
            rounded
            @click="doRemoveDomain(d)"
          />
        </div>
      </div>
    </div>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useToast } from 'primevue/usetoast'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import SelectButton from 'primevue/selectbutton'
import type { CustomerConfig } from '../types'
import {
  fetchCustomerConfig,
  addKeyword,
  removeKeyword,
  addMonitoredDomain,
  removeMonitoredDomain,
  ensureCustomer,
} from '../api'

const props = defineProps<{
  visible: boolean
  customers: string[]
}>()
defineEmits<{ 'update:visible': [value: boolean] }>()

const toast = useToast()
const activeCustomer = ref('')
const config = ref<CustomerConfig | null>(null)
const configLoading = ref(false)
const configError = ref('')
const newKeyword = ref('')
const newDomain = ref('')

watch(
  () => props.visible,
  (open) => {
    if (open && props.customers.length) {
      if (!activeCustomer.value) activeCustomer.value = props.customers[0]
      loadConfig()
    }
  }
)

async function loadConfig() {
  if (!activeCustomer.value) return
  configLoading.value = true
  configError.value = ''
  config.value = null
  try {
    await ensureCustomer(activeCustomer.value)
    config.value = await fetchCustomerConfig(activeCustomer.value)
  } catch (err) {
    configError.value = `Could not load config: ${err}`
  } finally {
    configLoading.value = false
  }
}

async function doAddKeyword() {
  const kw = newKeyword.value.trim().toLowerCase()
  if (!kw || !config.value) return
  try {
    await addKeyword(activeCustomer.value, kw)
    config.value.keywords.push(kw)
    config.value.keywords.sort()
    newKeyword.value = ''
    toast.add({ severity: 'success', summary: 'Keyword added', detail: kw, life: 2500 })
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Failed', detail: String(err), life: 4000 })
  }
}

async function doRemoveKeyword(kw: string) {
  if (!config.value) return
  try {
    await removeKeyword(activeCustomer.value, kw)
    config.value.keywords = config.value.keywords.filter(k => k !== kw)
    toast.add({ severity: 'info', summary: 'Keyword removed', detail: kw, life: 2500 })
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Failed', detail: String(err), life: 4000 })
  }
}

async function doAddDomain() {
  const d = newDomain.value.trim().toLowerCase()
  if (!d || !config.value) return
  try {
    await addMonitoredDomain(activeCustomer.value, d)
    config.value.domains.push(d)
    config.value.domains.sort()
    newDomain.value = ''
    toast.add({ severity: 'success', summary: 'Domain added', detail: d, life: 2500 })
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Failed', detail: String(err), life: 4000 })
  }
}

async function doRemoveDomain(d: string) {
  if (!config.value) return
  try {
    await removeMonitoredDomain(activeCustomer.value, d)
    config.value.domains = config.value.domains.filter(x => x !== d)
    toast.add({ severity: 'info', summary: 'Domain removed', detail: d, life: 2500 })
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Failed', detail: String(err), life: 4000 })
  }
}
</script>
