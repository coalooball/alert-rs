<template>
  <div class="association-model-container">
    <el-card class="config-card">
      <template #header>
        <div class="card-header">
          <span>自动推送配置</span>
          <el-button type="primary" @click="showAddDialog">新增配置</el-button>
        </div>
      </template>
      
      <el-table :data="configs" stripe style="width: 100%">
        <el-table-column prop="name" label="配置名称" width="200" />
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'">
              {{ row.enabled ? '启用' : '禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="window_minutes" label="时间窗口（分钟）" width="150" />
        <el-table-column prop="interval_seconds" label="执行间隔（秒）" width="150" />
        <el-table-column label="创建时间" width="180">
          <template #default="{ row }">
            {{ formatTime(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="更新时间" width="180">
          <template #default="{ row }">
            {{ formatTime(row.updated_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" fixed="right" width="200">
          <template #default="{ row }">
            <el-button size="small" @click="editConfig(row)">编辑</el-button>
            <el-button size="small" type="danger" @click="deleteConfig(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 推送日志 -->
    <el-card class="logs-card">
      <template #header>
        <div class="card-header">
          <span>推送日志</span>
          <el-select v-model="logAlertType" placeholder="告警类型" clearable style="width: 150px" @change="loadLogs">
            <el-option label="全部" :value="null" />
            <el-option label="网络攻击" :value="1" />
            <el-option label="恶意样本" :value="2" />
            <el-option label="主机行为" :value="3" />
          </el-select>
        </div>
      </template>

      <el-table :data="logs" stripe style="width: 100%">
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

    <!-- 添加/编辑对话框 -->
    <el-dialog
      v-model="dialogVisible"
      :title="dialogTitle"
      width="500px"
    >
      <el-form :model="formData" label-width="140px">
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
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="saveConfig">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import axios from 'axios'

// 配置列表
const configs = ref([])

// 日志相关
const logs = ref([])
const logPage = ref(1)
const logPageSize = ref(20)
const logTotal = ref(0)
const logAlertType = ref(null)

// 对话框相关
const dialogVisible = ref(false)
const dialogTitle = ref('新增配置')
const formData = ref({
  id: null,
  name: '',
  enabled: false,
  window_minutes: 60,
  interval_seconds: 60
})

// 格式化时间
const formatTime = (timestamp) => {
  if (!timestamp) return '-'
  const date = new Date(timestamp)
  return date.toLocaleString('zh-CN')
}

// 加载配置列表
const loadConfigs = async () => {
  try {
    const { data } = await axios.get('/api/auto/push-configs')
    configs.value = data
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

// 显示新增对话框
const showAddDialog = () => {
  dialogTitle.value = '新增配置'
  formData.value = {
    id: null,
    name: '',
    enabled: false,
    window_minutes: 60,
    interval_seconds: 60
  }
  dialogVisible.value = true
}

// 编辑配置
const editConfig = (row) => {
  dialogTitle.value = '编辑配置'
  formData.value = {
    id: row.id,
    name: row.name,
    enabled: row.enabled,
    window_minutes: row.window_minutes,
    interval_seconds: row.interval_seconds
  }
  dialogVisible.value = true
}

// 保存配置
const saveConfig = async () => {
  try {
    if (!formData.value.name) {
      ElMessage.warning('请输入配置名称')
      return
    }
    
    const payload = {
      name: formData.value.name,
      enabled: formData.value.enabled,
      window_minutes: formData.value.window_minutes,
      interval_seconds: formData.value.interval_seconds
    }
    
    if (formData.value.id) {
      // 更新
      await axios.put(`/api/auto/push-configs/${formData.value.id}`, payload)
      ElMessage.success('更新成功')
    } else {
      // 创建
      await axios.post('/api/auto/push-configs', payload)
      ElMessage.success('创建成功')
    }
    
    dialogVisible.value = false
    await loadConfigs()
  } catch (e) {
    ElMessage.error(e?.response?.data?.message || e.message || '保存失败')
  }
}

// 删除配置
const deleteConfig = async (row) => {
  try {
    await ElMessageBox.confirm('确定要删除这个配置吗？', '提示', {
      type: 'warning'
    })
    
    await axios.delete(`/api/auto/push-configs/${row.id}`)
    ElMessage.success('删除成功')
    await loadConfigs()
  } catch (e) {
    if (e !== 'cancel') {
      ElMessage.error(e?.response?.data?.message || e.message || '删除失败')
    }
  }
}

onMounted(() => {
  loadConfigs()
  loadLogs()
})
</script>

<style scoped>
.association-model-container {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.config-card {
  margin-bottom: 20px;
}

.logs-card {
  margin-top: 20px;
}
</style>


