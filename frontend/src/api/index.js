import axios from 'axios'

// 使用相对路径，适配任何部署环境
const API_BASE_URL = '/api'

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

export const getInvalidAlerts = (page = 1, pageSize = 20) => {
  return api.get('/invalid-alerts', {
    params: { page, page_size: pageSize }
  })
}

export const getAlarmTypes = () => {
  return api.get('/alarm-types')
}

