import axios from 'axios'

const API_BASE_URL = 'http://localhost:3000/api'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000
})

export const getNetworkAttacks = (page = 1, pageSize = 20) => {
  return api.get('/network-attacks', {
    params: { page, page_size: pageSize }
  })
}

export const getMaliciousSamples = (page = 1, pageSize = 20) => {
  return api.get('/malicious-samples', {
    params: { page, page_size: pageSize }
  })
}

export const getHostBehaviors = (page = 1, pageSize = 20) => {
  return api.get('/host-behaviors', {
    params: { page, page_size: pageSize }
  })
}

