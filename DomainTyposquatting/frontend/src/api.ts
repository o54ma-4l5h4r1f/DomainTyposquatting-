import type { DomainResponse, CustomerConfig, Customer } from './types'

const BASE = '/api'

export async function fetchDomains(params: {
  customers: string[]
  action_status?: string | null
  page?: number
  page_size?: number
  sort_field?: string
  sort_order?: string
}): Promise<DomainResponse> {
  const url = new URL(`${BASE}/domains`, window.location.origin)
  url.searchParams.set('customers', params.customers.join(','))
  if (params.action_status) url.searchParams.set('action_status', params.action_status)
  if (params.page) url.searchParams.set('page', params.page.toString())
  if (params.page_size) url.searchParams.set('page_size', params.page_size.toString())
  if (params.sort_field) url.searchParams.set('sort_field', params.sort_field)
  if (params.sort_order) url.searchParams.set('sort_order', params.sort_order)

  const res = await fetch(url.toString())
  if (!res.ok) throw new Error(`Failed to fetch domains: ${res.statusText}`)
  return res.json()
}

export async function setDomainAction(
  domain: string,
  action: string,
  customer: string
): Promise<void> {
  const res = await fetch(
    `${BASE}/domains/${encodeURIComponent(domain)}/action`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, customer }),
    }
  )
  if (!res.ok) throw new Error(`Failed to set action: ${res.statusText}`)
}

export async function undoDomainAction(
  domain: string,
  customer: string
): Promise<void> {
  const url = `${BASE}/domains/${encodeURIComponent(domain)}/action?customer=${encodeURIComponent(customer)}`
  const res = await fetch(url, { method: 'DELETE' })
  if (!res.ok) throw new Error(`Failed to undo action: ${res.statusText}`)
}

export async function fetchCustomers(): Promise<Customer[]> {
  const res = await fetch(`${BASE}/customers`)
  if (!res.ok) throw new Error(`Failed to fetch customers: ${res.statusText}`)
  const data = await res.json()
  return data.customers
}

/** Ensure a customer row exists (upsert — safe to call repeatedly). */
export async function ensureCustomer(
  name: string,
  tier: string = 'standard'
): Promise<void> {
  await fetch(`${BASE}/customers`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, tier }),
  })
}

export async function fetchCustomerConfig(
  name: string
): Promise<CustomerConfig> {
  const res = await fetch(
    `${BASE}/customers/${encodeURIComponent(name)}/config`
  )
  if (!res.ok) throw new Error(`Failed to fetch config: ${res.statusText}`)
  return res.json()
}

export async function addKeyword(
  customer: string,
  keyword: string
): Promise<void> {
  const res = await fetch(
    `${BASE}/customers/${encodeURIComponent(customer)}/keywords`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keyword }),
    }
  )
  if (!res.ok) throw new Error(`Failed to add keyword: ${res.statusText}`)
}

export async function removeKeyword(
  customer: string,
  keyword: string
): Promise<void> {
  const res = await fetch(
    `${BASE}/customers/${encodeURIComponent(customer)}/keywords/${encodeURIComponent(keyword)}`,
    { method: 'DELETE' }
  )
  if (!res.ok) throw new Error(`Failed to remove keyword: ${res.statusText}`)
}

export async function addMonitoredDomain(
  customer: string,
  domain: string
): Promise<void> {
  const res = await fetch(
    `${BASE}/customers/${encodeURIComponent(customer)}/domains`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    }
  )
  if (!res.ok) throw new Error(`Failed to add domain: ${res.statusText}`)
}

export async function removeMonitoredDomain(
  customer: string,
  domain: string
): Promise<void> {
  const res = await fetch(
    `${BASE}/customers/${encodeURIComponent(customer)}/domains/${encodeURIComponent(domain)}`,
    { method: 'DELETE' }
  )
  if (!res.ok) throw new Error(`Failed to remove domain: ${res.statusText}`)
}
