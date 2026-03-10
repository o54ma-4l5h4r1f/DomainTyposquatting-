<template>
  <div class="dashboard">
    <!-- Toolbar -->
    <Toolbar class="dashboard-toolbar">
      <template #start>
        <SelectButton
          v-model="filterStatus"
          :options="filterOptions"
          optionLabel="label"
          optionValue="value"
          :allowEmpty="false"
          @change="resetAndLoad"
        />
      </template>
      <template #end>
        <Button
          label="Configure"
          icon="pi pi-cog"
          severity="secondary"
          size="small"
          @click="showConfig = true"
        />
        <Button
          icon="pi pi-refresh"
          severity="secondary"
          size="small"
          style="margin-left: 0.5rem"
          @click="loadDomains"
          :loading="loading"
        />
      </template>
    </Toolbar>

    <!-- Data table -->
    <DataTable
      :value="domains"
      lazy
      paginator
      :rows="pageSize"
      :totalRecords="totalRecords"
      :loading="loading"
      @page="onPage"
      v-model:expandedRows="expandedRows"
      dataKey="domain"
      stripedRows
      class="domain-table"
      :rowsPerPageOptions="[10, 25, 50]"
      paginatorTemplate="FirstPageLink PrevPageLink PageLinks NextPageLink LastPageLink RowsPerPageDropdown"
    >
      <template #empty>
        <div style="text-align: center; padding: 2rem; color: #8892b0">
          No domains found.
        </div>
      </template>

      <Column expander style="width: 3rem" />

      <Column field="domain" header="Domain" style="min-width: 14rem">
        <template #body="{ data }">
          <span style="font-family: monospace; font-weight: 500">{{ data.domain }}</span>
        </template>
      </Column>

      <Column field="source" header="Source" style="width: 7rem">
        <template #body="{ data }">
          <Tag
            :value="data.source || '-'"
            :severity="data.source === 'dnstwist' ? 'info' : data.source === 'whoisds' ? 'warn' : 'secondary'"
          />
        </template>
      </Column>

      <Column field="fuzzer" header="Fuzzer" style="width: 9rem">
        <template #body="{ data }">{{ data.fuzzer || '-' }}</template>
      </Column>

      <Column field="first_seen_at" header="First Seen" style="width: 9rem">
        <template #body="{ data }">{{ formatDate(data.first_seen_at) }}</template>
      </Column>

      <Column field="whois_created" header="Registered" style="width: 9rem">
        <template #body="{ data }">{{ data.whois_created || '-' }}</template>
      </Column>

      <Column field="whois_registrar" header="Registrar" style="width: 10rem">
        <template #body="{ data }">{{ data.whois_registrar || '-' }}</template>
      </Column>

      <Column field="action_status" header="Status" style="width: 8rem">
        <template #body="{ data }">
          <Tag
            v-if="data.action_status"
            :value="statusLabel(data.action_status)"
            :severity="actionSeverity(data.action_status)"
          />
          <Tag v-else value="Pending" severity="secondary" />
        </template>
      </Column>

      <Column header="Actions" style="min-width: 10rem">
        <template #body="{ data }">
          <div class="action-buttons">
            <Button
              icon="pi pi-times"
              severity="danger"
              size="small"
              rounded
              text
              v-tooltip.top="'Block'"
              @click="markDomain(data, 'blocked')"
              :disabled="data.action_status === 'blocked'"
            />
            <Button
              icon="pi pi-check"
              severity="success"
              size="small"
              rounded
              text
              v-tooltip.top="'Safe'"
              @click="markDomain(data, 'safe')"
              :disabled="data.action_status === 'safe'"
            />
            <Button
              icon="pi pi-flag"
              severity="warn"
              size="small"
              rounded
              text
              v-tooltip.top="'Request Takedown'"
              @click="markDomain(data, 'takedown_requested')"
              :disabled="data.action_status === 'takedown_requested'"
            />
            <Button
              v-if="data.action_status"
              icon="pi pi-undo"
              severity="secondary"
              size="small"
              rounded
              text
              v-tooltip.top="'Undo'"
              @click="undoMark(data)"
            />
          </div>
        </template>
      </Column>

      <!-- Expanded row: full domain detail -->
      <template #expansion="{ data }">
        <div class="domain-detail">
          <div class="detail-grid">
            <div class="detail-section">
              <h4>WHOIS</h4>
              <div class="detail-row"><span>Registrar:</span><span>{{ data.whois_registrar || '-' }}</span></div>
              <div class="detail-row"><span>Registrant:</span><span>{{ data.whois_registrant || '-' }}</span></div>
              <div class="detail-row"><span>Country:</span><span>{{ data.whois_country || '-' }}</span></div>
              <div class="detail-row"><span>Created:</span><span>{{ data.whois_created || '-' }}</span></div>
              <div class="detail-row"><span>Updated:</span><span>{{ data.whois_updated || '-' }}</span></div>
              <div class="detail-row"><span>Expires:</span><span>{{ data.whois_expires || '-' }}</span></div>
            </div>
          </div>

          <div class="detail-meta">
            <span v-if="data.original_domain">Original: <strong>{{ data.original_domain }}</strong></span>
            <span v-if="data.nrd_keyword_matched"> &middot; Keyword: <strong>{{ data.nrd_keyword_matched }}</strong></span>
            <span v-if="data.nrd_date"> &middot; NRD Date: {{ data.nrd_date }}</span>
            <span v-if="data.action_taken_at"> &middot; Action at: {{ formatDate(data.action_taken_at) }}</span>
          </div>
        </div>
      </template>
    </DataTable>

    <ConfigDialog v-model:visible="showConfig" :customers="customers" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Toolbar from 'primevue/toolbar'
import SelectButton from 'primevue/selectbutton'
import ConfigDialog from './ConfigDialog.vue'
import type { Domain } from '../types'
import { fetchDomains, setDomainAction, undoDomainAction } from '../api'

const props = defineProps<{ customers: string[] }>()
const toast = useToast()

const domains = ref<Domain[]>([])
const expandedRows = ref<Record<string, boolean>>({})
const loading = ref(false)
const totalRecords = ref(0)
const currentPage = ref(1)
const pageSize = ref(25)
const showConfig = ref(false)

const filterOptions = [
  { label: 'Pending', value: 'pending' },
  { label: 'All', value: 'all' },
  { label: 'Blocked', value: 'blocked' },
  { label: 'Safe', value: 'safe' },
  { label: 'Takedown', value: 'takedown_requested' },
]
const filterStatus = ref('pending')

async function loadDomains() {
  loading.value = true
  try {
    const status = filterStatus.value === 'all' ? undefined : filterStatus.value
    const resp = await fetchDomains({
      customers: props.customers,
      action_status: status,
      page: currentPage.value,
      page_size: pageSize.value,
    })
    domains.value = resp.domains
    totalRecords.value = resp.total
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Load failed', detail: String(err), life: 4000 })
  } finally {
    loading.value = false
  }
}

function onPage(event: { page: number; rows: number }) {
  currentPage.value = event.page + 1
  pageSize.value = event.rows
  loadDomains()
}

function resetAndLoad() {
  currentPage.value = 1
  loadDomains()
}

async function markDomain(row: Domain, action: string) {
  if (!row.customer) return
  try {
    await setDomainAction(row.domain, action, row.customer)
    row.action_status = action
    toast.add({ severity: 'success', summary: 'Done', detail: `${row.domain} marked as ${action}`, life: 2500 })
    // If filtering by pending, remove from view after action
    if (filterStatus.value === 'pending') {
      domains.value = domains.value.filter(d => d.domain !== row.domain)
      totalRecords.value = Math.max(0, totalRecords.value - 1)
    }
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Action failed', detail: String(err), life: 4000 })
  }
}

async function undoMark(row: Domain) {
  if (!row.customer) return
  try {
    await undoDomainAction(row.domain, row.customer)
    row.action_status = null
    row.action_taken_at = null
    toast.add({ severity: 'info', summary: 'Undone', detail: `${row.domain} reset to pending`, life: 2500 })
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Undo failed', detail: String(err), life: 4000 })
  }
}

function formatDate(val: string | null): string {
  if (!val) return '-'
  try {
    return new Date(val).toLocaleDateString('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    })
  } catch {
    return val
  }
}

function statusLabel(status: string): string {
  const map: Record<string, string> = {
    blocked: 'Blocked',
    safe: 'Safe',
    takedown_requested: 'Takedown',
  }
  return map[status] || status
}

function actionSeverity(status: string): string {
  const map: Record<string, string> = {
    blocked: 'danger',
    safe: 'success',
    takedown_requested: 'warn',
  }
  return map[status] || 'secondary'
}

onMounted(loadDomains)
</script>
