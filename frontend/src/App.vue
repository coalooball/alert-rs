<template>
  <div class="app-container">
    <el-container>
      <el-header>
        <div class="header-content">
          <h1>🛡️ 网络安全告警监控系统</h1>
          <el-tag :type="isConnected ? 'success' : 'danger'" size="large">
            {{ isConnected ? '● 实时连接' : '○ 已断开' }}
          </el-tag>
        </div>
      </el-header>
      
      <el-main>
        <!-- 统计卡片 -->
        <el-row :gutter="20" class="stats-row">
          <el-col :span="8">
            <el-card shadow="hover" class="stat-card network-card">
              <div class="stat-content">
                <div class="stat-icon">🔴</div>
                <div class="stat-info">
                  <div class="stat-label">网络攻击告警</div>
                  <div class="stat-value">{{ networkAlerts.length }}</div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="8">
            <el-card shadow="hover" class="stat-card sample-card">
              <div class="stat-content">
                <div class="stat-icon">🟠</div>
                <div class="stat-info">
                  <div class="stat-label">恶意样本告警</div>
                  <div class="stat-value">{{ sampleAlerts.length }}</div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="8">
            <el-card shadow="hover" class="stat-card host-card">
              <div class="stat-content">
                <div class="stat-icon">🟡</div>
                <div class="stat-info">
                  <div class="stat-label">主机行为告警</div>
                  <div class="stat-value">{{ hostAlerts.length }}</div>
                </div>
              </div>
            </el-card>
          </el-col>
        </el-row>

        <!-- 告警类型切换 -->
        <el-card shadow="never" class="control-card">
          <el-radio-group v-model="activeTab" size="large">
            <el-radio-button value="network">
              🔴 网络攻击告警 ({{ networkAlerts.length }})
            </el-radio-button>
            <el-radio-button value="sample">
              🟠 恶意样本告警 ({{ sampleAlerts.length }})
            </el-radio-button>
            <el-radio-button value="host">
              🟡 主机行为告警 ({{ hostAlerts.length }})
            </el-radio-button>
          </el-radio-group>
          
          <el-space style="margin-left: 20px;">
            <el-button 
              :type="isConnected ? 'danger' : 'success'" 
              @click="toggleConnection"
              :icon="isConnected ? 'VideoPause' : 'VideoPlay'">
              {{ isConnected ? '暂停推送' : '开始推送' }}
            </el-button>
            <el-button @click="clearAlerts" icon="Delete">清空数据</el-button>
            <el-switch
              v-model="autoScroll"
              active-text="自动滚动"
              inactive-text=""
            />
          </el-space>
        </el-card>

        <!-- 告警列表 -->
        <el-card shadow="never" class="alerts-card">
          <!-- 网络攻击告警 -->
          <div v-show="activeTab === 'network'" class="alerts-container" ref="networkContainer">
            <el-empty v-if="networkAlerts.length === 0" description="暂无网络攻击告警" />
            <el-timeline v-else>
              <el-timeline-item
                v-for="alert in networkAlerts"
                :key="alert.alarm_id"
                :timestamp="formatTime(alert.alarm_date)"
                placement="top"
                :type="getSeverityType(alert.alarm_severity)"
                :hollow="false"
                size="large">
                <el-card shadow="hover" class="alert-item">
                  <template #header>
                    <div class="alert-header">
                      <span class="alert-title">{{ alert.alarm_name }}</span>
                      <el-tag :type="getSeverityType(alert.alarm_severity)">
                        {{ getSeverityText(alert.alarm_severity) }}
                      </el-tag>
                    </div>
                  </template>
                  <el-descriptions :column="2" border size="small">
                    <el-descriptions-item label="告警ID">{{ alert.alarm_id }}</el-descriptions-item>
                    <el-descriptions-item label="协议">{{ alert.protocol }}</el-descriptions-item>
                    <el-descriptions-item label="源IP">{{ alert.src_ip }}:{{ alert.src_port }}</el-descriptions-item>
                    <el-descriptions-item label="目标IP">{{ alert.dst_ip }}:{{ alert.dst_port }}</el-descriptions-item>
                    <el-descriptions-item label="攻击阶段" :span="2">{{ alert.attack_stage }}</el-descriptions-item>
                    <el-descriptions-item label="APT组织" :span="2" v-if="alert.apt_group">
                      <el-tag type="danger">{{ alert.apt_group }}</el-tag>
                    </el-descriptions-item>
                    <el-descriptions-item label="描述" :span="2">{{ alert.alarm_description }}</el-descriptions-item>
                  </el-descriptions>
                </el-card>
              </el-timeline-item>
            </el-timeline>
          </div>

          <!-- 恶意样本告警 -->
          <div v-show="activeTab === 'sample'" class="alerts-container" ref="sampleContainer">
            <el-empty v-if="sampleAlerts.length === 0" description="暂无恶意样本告警" />
            <el-timeline v-else>
              <el-timeline-item
                v-for="alert in sampleAlerts"
                :key="alert.alarm_id"
                :timestamp="formatTime(alert.alarm_date)"
                placement="top"
                :type="getSeverityType(alert.alarm_severity)"
                :hollow="false"
                size="large">
                <el-card shadow="hover" class="alert-item">
                  <template #header>
                    <div class="alert-header">
                      <span class="alert-title">{{ alert.alarm_name }}</span>
                      <el-tag :type="getSeverityType(alert.alarm_severity)">
                        {{ getSeverityText(alert.alarm_severity) }}
                      </el-tag>
                    </div>
                  </template>
                  <el-descriptions :column="2" border size="small">
                    <el-descriptions-item label="告警ID">{{ alert.alarm_id }}</el-descriptions-item>
                    <el-descriptions-item label="样本家族">
                      <el-tag type="warning">{{ alert.sample_family }}</el-tag>
                    </el-descriptions-item>
                    <el-descriptions-item label="文件名">{{ alert.sample_original_name }}</el-descriptions-item>
                    <el-descriptions-item label="文件大小">{{ formatFileSize(alert.file_size) }}</el-descriptions-item>
                    <el-descriptions-item label="MD5" :span="2">
                      <code class="hash-code">{{ alert.md5 }}</code>
                    </el-descriptions-item>
                    <el-descriptions-item label="SHA256" :span="2">
                      <code class="hash-code">{{ alert.sha256 }}</code>
                    </el-descriptions-item>
                    <el-descriptions-item label="平台" :span="2">{{ alert.target_platform }}</el-descriptions-item>
                    <el-descriptions-item label="描述" :span="2">{{ alert.alarm_description }}</el-descriptions-item>
                  </el-descriptions>
                </el-card>
              </el-timeline-item>
            </el-timeline>
          </div>

          <!-- 主机行为告警 -->
          <div v-show="activeTab === 'host'" class="alerts-container" ref="hostContainer">
            <el-empty v-if="hostAlerts.length === 0" description="暂无主机行为告警" />
            <el-timeline v-else>
              <el-timeline-item
                v-for="alert in hostAlerts"
                :key="alert.alarm_id"
                :timestamp="formatTime(alert.alarm_date)"
                placement="top"
                :type="getSeverityType(alert.alarm_severity)"
                :hollow="false"
                size="large">
                <el-card shadow="hover" class="alert-item">
                  <template #header>
                    <div class="alert-header">
                      <span class="alert-title">{{ alert.alarm_name }}</span>
                      <el-tag :type="getSeverityType(alert.alarm_severity)">
                        {{ getSeverityText(alert.alarm_severity) }}
                      </el-tag>
                    </div>
                  </template>
                  <el-descriptions :column="2" border size="small">
                    <el-descriptions-item label="告警ID">{{ alert.alarm_id }}</el-descriptions-item>
                    <el-descriptions-item label="主机名">{{ alert.host_name }}</el-descriptions-item>
                    <el-descriptions-item label="主机IP">{{ alert.terminal_ip }}</el-descriptions-item>
                    <el-descriptions-item label="操作系统">{{ alert.terminal_os }}</el-descriptions-item>
                    <el-descriptions-item label="用户账户">{{ alert.user_account }}</el-descriptions-item>
                    <el-descriptions-item label="终端ID">{{ alert.terminal_id }}</el-descriptions-item>
                    <el-descriptions-item label="进程路径" :span="2">
                      <code class="path-code">{{ alert.dst_process_path }}</code>
                    </el-descriptions-item>
                    <el-descriptions-item label="进程命令行" :span="2">
                      <code class="path-code">{{ alert.dst_process_cli }}</code>
                    </el-descriptions-item>
                    <el-descriptions-item label="描述" :span="2">{{ alert.alarm_description }}</el-descriptions-item>
                  </el-descriptions>
                </el-card>
              </el-timeline-item>
            </el-timeline>
          </div>
        </el-card>
      </el-main>
      
      <el-footer>
        <div class="footer-content">
          <p>🦀 Powered by Rust Axum + Vue3 | SSE 实时推送 | 网络安全告警监控系统</p>
        </div>
      </el-footer>
    </el-container>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { ElMessage } from 'element-plus'

// 状态管理
const networkAlerts = ref([])
const sampleAlerts = ref([])
const hostAlerts = ref([])
const activeTab = ref('network')
const isConnected = ref(false)
const autoScroll = ref(true)

// 容器引用
const networkContainer = ref(null)
const sampleContainer = ref(null)
const hostContainer = ref(null)

// EventSource 连接
let networkSource = null
let sampleSource = null
let hostSource = null

// 连接 SSE
const connectSSE = () => {
  try {
    // 网络攻击告警流
    networkSource = new EventSource('http://localhost:3000/api/alerts/network-attack/stream')
    networkSource.onmessage = (event) => {
      const alert = JSON.parse(event.data)
      networkAlerts.value.unshift(alert)
      if (networkAlerts.value.length > 50) networkAlerts.value.pop()
      if (activeTab.value === 'network' && autoScroll.value) {
        scrollToTop('network')
      }
    }
    networkSource.onerror = () => {
      console.error('网络攻击告警流连接错误')
    }

    // 恶意样本告警流
    sampleSource = new EventSource('http://localhost:3000/api/alerts/malicious-sample/stream')
    sampleSource.onmessage = (event) => {
      const alert = JSON.parse(event.data)
      sampleAlerts.value.unshift(alert)
      if (sampleAlerts.value.length > 50) sampleAlerts.value.pop()
      if (activeTab.value === 'sample' && autoScroll.value) {
        scrollToTop('sample')
      }
    }
    sampleSource.onerror = () => {
      console.error('恶意样本告警流连接错误')
    }

    // 主机行为告警流
    hostSource = new EventSource('http://localhost:3000/api/alerts/host-behavior/stream')
    hostSource.onmessage = (event) => {
      const alert = JSON.parse(event.data)
      hostAlerts.value.unshift(alert)
      if (hostAlerts.value.length > 50) hostAlerts.value.pop()
      if (activeTab.value === 'host' && autoScroll.value) {
        scrollToTop('host')
      }
    }
    hostSource.onerror = () => {
      console.error('主机行为告警流连接错误')
    }

    isConnected.value = true
    ElMessage.success('SSE 连接成功，开始接收告警数据')
  } catch (error) {
    ElMessage.error('连接失败: ' + error.message)
  }
}

// 断开 SSE
const disconnectSSE = () => {
  if (networkSource) networkSource.close()
  if (sampleSource) sampleSource.close()
  if (hostSource) hostSource.close()
  isConnected.value = false
  ElMessage.info('已停止接收告警数据')
}

// 切换连接状态
const toggleConnection = () => {
  if (isConnected.value) {
    disconnectSSE()
  } else {
    connectSSE()
  }
}

// 清空告警数据
const clearAlerts = () => {
  networkAlerts.value = []
  sampleAlerts.value = []
  hostAlerts.value = []
  ElMessage.success('已清空所有告警数据')
}

// 滚动到顶部
const scrollToTop = (type) => {
  nextTick(() => {
    const container = type === 'network' ? networkContainer.value 
                    : type === 'sample' ? sampleContainer.value 
                    : hostContainer.value
    if (container) {
      container.scrollTop = 0
    }
  })
}

// 格式化时间
const formatTime = (timestamp) => {
  const date = new Date(timestamp)
  return date.toLocaleString('zh-CN')
}

// 格式化文件大小
const formatFileSize = (bytes) => {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
}

// 获取严重程度类型
const getSeverityType = (severity) => {
  switch (severity) {
    case 3: return 'danger'
    case 2: return 'warning'
    case 1: return 'info'
    default: return 'info'
  }
}

// 获取严重程度文本
const getSeverityText = (severity) => {
  switch (severity) {
    case 3: return '高危'
    case 2: return '中危'
    case 1: return '低危'
    default: return '未知'
  }
}

// 生命周期
onMounted(() => {
  connectSSE()
})

onUnmounted(() => {
  disconnectSSE()
})
</script>

<style scoped>
.app-container {
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.el-container {
  min-height: 100vh;
}

.el-header {
  background-color: #fff;
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
  display: flex;
  align-items: center;
  padding: 0 40px;
}

.header-content {
  width: 100%;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-content h1 {
  margin: 0;
  color: #303133;
  font-size: 24px;
}

.el-main {
  padding: 30px;
  max-width: 1400px;
  margin: 0 auto;
  width: 100%;
}

.stats-row {
  margin-bottom: 20px;
}

.stat-card {
  cursor: pointer;
  transition: transform 0.3s;
}

.stat-card:hover {
  transform: translateY(-5px);
}

.stat-content {
  display: flex;
  align-items: center;
  gap: 20px;
}

.stat-icon {
  font-size: 48px;
}

.stat-info {
  flex: 1;
}

.stat-label {
  font-size: 14px;
  color: #909399;
  margin-bottom: 8px;
}

.stat-value {
  font-size: 32px;
  font-weight: bold;
  color: #303133;
}

.network-card { border-left: 4px solid #f56c6c; }
.sample-card { border-left: 4px solid #e6a23c; }
.host-card { border-left: 4px solid #f0c940; }

.control-card {
  margin-bottom: 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.alerts-card {
  background-color: rgba(255, 255, 255, 0.98);
}

.alerts-container {
  max-height: 600px;
  overflow-y: auto;
  padding: 20px;
}

.alert-item {
  margin-bottom: 10px;
}

.alert-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.alert-title {
  font-size: 16px;
  font-weight: bold;
  color: #303133;
}

.hash-code {
  font-family: 'Courier New', monospace;
  font-size: 12px;
  color: #606266;
  background: #f5f7fa;
  padding: 2px 6px;
  border-radius: 3px;
  word-break: break-all;
}

.path-code {
  font-family: 'Courier New', monospace;
  font-size: 13px;
  color: #409eff;
  background: #ecf5ff;
  padding: 2px 8px;
  border-radius: 3px;
}

.el-footer {
  background-color: #fff;
  box-shadow: 0 -2px 12px 0 rgba(0, 0, 0, 0.1);
  display: flex;
  align-items: center;
  justify-content: center;
  height: 60px;
}

.footer-content {
  text-align: center;
  color: #909399;
}

.footer-content p {
  margin: 0;
  font-size: 14px;
}

/* 滚动条样式 */
.alerts-container::-webkit-scrollbar {
  width: 8px;
}

.alerts-container::-webkit-scrollbar-track {
  background: #f1f1f1;
  border-radius: 4px;
}

.alerts-container::-webkit-scrollbar-thumb {
  background: #888;
  border-radius: 4px;
}

.alerts-container::-webkit-scrollbar-thumb:hover {
  background: #555;
}
</style>
