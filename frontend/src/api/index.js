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

export const getThreatEvents = (page = 1, pageSize = 20) => {
  return api.get('/threat-events', {
    params: { page, page_size: pageSize }
  })
}

export const updateThreatEvent = (id, data) => {
  return api.put(`/threat-events/${id}`, data)
}

// 根据收敛告警ID查询原始告警
export const getRawNetworkAttacksByConvergedId = (convergedId) => {
  return api.get(`/network-attacks/${convergedId}/raw`)
}

export const getRawMaliciousSamplesByConvergedId = (convergedId) => {
  return api.get(`/malicious-samples/${convergedId}/raw`)
}

export const getRawHostBehaviorsByConvergedId = (convergedId) => {
  return api.get(`/host-behaviors/${convergedId}/raw`)
}

// ==================== 标签管理 API ====================

// 获取所有标签（不分页）
export const getAllTags = () => {
  return api.get('/tags/all')
}

// 获取标签列表（分页）
export const getTags = (page = 1, pageSize = 10, search = '', category = '') => {
  return api.get('/tags', {
    params: { page, page_size: pageSize, search, category }
  })
}

// 根据 ID 获取单个标签
export const getTagById = (id) => {
  return api.get(`/tags/${id}`)
}

// 创建标签
export const createTag = (data) => {
  return api.post('/tags', data)
}

// 更新标签
export const updateTag = (id, data) => {
  return api.put(`/tags/${id}`, data)
}

// 删除标签
export const deleteTag = (id) => {
  return api.delete(`/tags/${id}`)
}

// ==================== 告警-标签关联 API ====================

// 获取告警的所有标签
// alertType: 'network_attack', 'malicious_sample', 'host_behavior'
export const getAlertTags = (alertType, alertId) => {
  return api.get(`/alerts/${alertType}/${alertId}/tags`)
}

// 给告警添加单个标签
export const addAlertTag = (alertType, alertId, tagId) => {
  return api.post(`/alerts/${alertType}/${alertId}/tags`, { tag_id: tagId })
}

// 批量给告警添加标签
export const batchAddAlertTags = (alertType, alertId, tagIds) => {
  return api.post(`/alerts/${alertType}/${alertId}/tags/batch`, { tag_ids: tagIds })
}

// 从告警中移除标签
export const removeAlertTag = (alertType, alertId, tagId) => {
  return api.delete(`/alerts/${alertType}/${alertId}/tags/${tagId}`)
}

// 移除告警的所有标签
export const removeAllAlertTags = (alertType, alertId) => {
  return api.delete(`/alerts/${alertType}/${alertId}/tags`)
}

// 获取某个标签关联的所有告警
export const getAlertsByTag = (tagId) => {
  return api.get(`/tags/${tagId}/alerts`)
}
