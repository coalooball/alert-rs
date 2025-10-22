<template>
  <div class="association-model-container">
    <el-card class="config-card">
      <template #header>
        <div class="card-header">
          <span><i class="el-icon-setting"></i> 自动推送配置</span>
          <el-button type="primary" @click="saveConfig">保存配置</el-button>
        </div>
      </template>
      
      <el-form :model="formData" label-width="140px" class="config-form">
        <el-form-item label="配置名称">
          <el-input v-model="formData.name" placeholder="请输入配置名称" />
        </el-form-item>
        <el-form-item label="自动推送开关">
          <el-switch v-model="formData.enabled" />
        </el-form-item>
        <el-form-item label="时间窗口（分钟）">
          <el-input-number v-model="formData.window_minutes" :min="1" :max="1440" />
        </el-form-item>
        <el-form-item label="执行间隔（秒）">
          <el-input-number v-model="formData.interval_seconds" :min="5" :max="86400" />
        </el-form-item>
        <el-form-item label="创建时间">
          <span>{{ formatTime(formData.created_at) }}</span>
        </el-form-item>
        <el-form-item label="更新时间">
          <span>{{ formatTime(formData.updated_at) }}</span>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 推送日志 -->
    <el-card class="logs-card">
      <template #header>
        <div class="card-header">
          <span><i class="el-icon-document"></i> 推送日志</span>
          <el-select v-model="logAlertType" placeholder="告警类型" clearable style="width: 150px" @change="loadLogs">
            <el-option label="全部" :value="null" />
            <el-option label="网络攻击" :value="1" />
            <el-option label="恶意样本" :value="2" />
            <el-option label="主机行为" :value="3" />
          </el-select>
        </div>
      </template>

      <el-table :data="logs" stripe style="width: 100%">
        <el-table-column prop="id" label="日志ID" width="280" />
        <el-table-column prop="alert_type_name" label="告警类型" width="120" />
        <el-table-column prop="converged_id" label="收敛告警ID" width="280" />
        <el-table-column label="推送时间" width="180">
          <template #default="{ row }">
            {{ formatTime(row.pushed_at) }}
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        v-model:current-page="logPage"
        v-model:page-size="logPageSize"
        :total="logTotal"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next"
        @current-change="loadLogs"
        @size-change="loadLogs"
        style="margin-top: 20px; justify-content: center"
      />
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'

// 表单数据
const formData = ref({
  id: null,
  name: '',
  enabled: false,
  window_minutes: 60,
  interval_seconds: 60,
  created_at: null,
  updated_at: null,
})

// 日志相关
const logs = ref([])
const logPage = ref(1)
const logPageSize = ref(20)
const logTotal = ref(0)
const logAlertType = ref(null)

// 格式化时间
const formatTime = (timestamp) => {
  if (!timestamp) return '-'
  const date = new Date(timestamp)
  return date.toLocaleString('zh-CN')
}

// 加载配置
const loadConfig = async () => {
  try {
    const { data } = await axios.get('/api/auto/push-config')
    formData.value = data
  } catch (e) {
    ElMessage.error(e?.response?.data?.message || e.message || '读取配置失败')
  }
}

// 加载推送日志
const loadLogs = async () => {
  try {
    const params = {
      page: logPage.value,
      page_size: logPageSize.value
    }
    if (logAlertType.value !== null) {
      params.alert_type = logAlertType.value
    }
    const { data } = await axios.get('/api/auto/push-logs', { params })
    logs.value = data.logs
    logTotal.value = data.total
  } catch (e) {
    ElMessage.error(e?.response?.data?.message || e.message || '读取日志失败')
  }
}

// 保存配置
const saveConfig = async () => {
  try {
    if (!formData.value.name) {
      ElMessage.warning('请输入配置名称')
      return
    }
    
    const payload = {
      id: formData.value.id, // 确保 id 被包含
      name: formData.value.name,
      enabled: formData.value.enabled,
      window_minutes: formData.value.window_minutes,
      interval_seconds: formData.value.interval_seconds
    }
    
    await axios.put(`/api/auto/push-config`, payload)
    ElMessage.success('配置已保存')
    await loadConfig() // 重新加载以更新 created_at/updated_at
  } catch (e) {
    ElMessage.error(e?.response?.data?.message || e.message || '保存失败')
  }
}

onMounted(() => {
  loadConfig()
  loadLogs()
})
</script>

<style scoped>
.association-model-container {
  padding: 24px;
  background-color: #f5f7fa;
  min-height: 100vh;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 16px;
  font-weight: bold;
  color: #303133;
}

.card-header span i {
  margin-right: 8px;
  font-size: 18px;
  vertical-align: middle;
}

.config-card {
  margin-bottom: 24px;
  border-radius: 8px;
  box-shadow: 0 2px 12px rgba(0,0,0,0.1);
}

.config-form {
  max-width: 600px;
  padding: 0 20px;
}

.logs-card {
  border-radius: 8px;
  box-shadow: 0 2px 12px rgba(0,0,0,0.1);
}

el-table {
  margin-top: 16px;
}

el-pagination {
  margin-top: 24px;
  justify-content: center;
}
</style>


