export interface Domain {
  domain: string
  customer: string | null
  original_domain: string | null
  source: string | null
  first_seen_at: string | null
  last_updated_at: string | null
  fuzzer: string | null
  dns_a: string | null
  dns_aaaa: string | null
  dns_mx: string | null
  dns_ns: string | null
  whois_registrar: string | null
  whois_created: string | null
  whois_updated: string | null
  whois_expires: string | null
  whois_registrant: string | null
  whois_country: string | null
  geoip_country: string | null
  http_banner: string | null
  smtp_banner: string | null
  lsh_ssdeep: string | null
  lsh_tlsh: string | null
  mx_can_intercept: number | null
  nrd_date: string | null
  nrd_keyword_matched: string | null
  action_status: string | null
  action_taken_at: string | null
  action_taken_by: string | null
}

export interface DomainResponse {
  domains: Domain[]
  total: number
  page: number
  page_size: number
}

export interface Customer {
  name: string
  tier: string
  active: boolean
  created_at: string
  updated_at: string
}

export interface CustomerConfig {
  customer: Customer
  keywords: string[]
  domains: string[]
}
