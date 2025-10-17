<template>
  <div class="page-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>终端日志</h2>
          <el-button type="primary" @click="loadData" :loading="loading">
            <el-icon><Refresh /></el-icon> 刷新
          </el-button>
        </div>
      </template>

      <!-- 搜索表单 -->
      <div class="search-form">
        <el-form :inline="true" :model="searchForm">
          <el-form-item label="主机名">
            <el-input v-model="searchForm.host_name" placeholder="请输入主机名" clearable style="width: 180px" />
          </el-form-item>
          <el-form-item label="终端IP">
            <el-input v-model="searchForm.terminal_ip" placeholder="请输入终端IP" clearable style="width: 150px" />
          </el-form-item>
          <el-form-item label="用户账号">
            <el-input v-model="searchForm.user_account" placeholder="请输入用户账号" clearable style="width: 150px" />
          </el-form-item>
          <el-form-item label="操作系统">
            <el-input v-model="searchForm.terminal_os" placeholder="请输入操作系统" clearable style="width: 150px" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="handleSearch">搜索</el-button>
            <el-button @click="handleReset">重置</el-button>
          </el-form-item>
        </el-form>
      </div>

      <el-table :data="filteredTableData" v-loading="loading" stripe border style="width: 100%">
        <el-table-column type="index" label="序号" width="60" />
        <el-table-column prop="alarm_severity" label="威胁等级" width="100" align="center">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.alarm_severity)">
              {{ getSeverityText(row.alarm_severity) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="alarm_type" label="告警类型" width="150" show-overflow-tooltip>
          <template #default="{ row }">
            {{ getAlarmTypeName() }}
          </template>
        </el-table-column>
        <el-table-column prop="alarm_subtype" label="告警子类型" width="150" show-overflow-tooltip>
          <template #default="{ row }">
            {{ getAlarmSubtypeName(row.alarm_subtype) }}
          </template>
        </el-table-column>
        <el-table-column prop="host_name" label="主机名" width="180" show-overflow-tooltip />
        <el-table-column prop="terminal_ip" label="终端IP" width="150" />
        <el-table-column prop="user_account" label="用户账号" width="150" show-overflow-tooltip />
        <el-table-column prop="terminal_os" label="操作系统" width="150" />
        <el-table-column prop="src_process_path" label="源进程路径" width="250" show-overflow-tooltip />
        <el-table-column prop="src_ip" label="源IP" width="150" />
        <el-table-column prop="src_port" label="源端口" width="100" />
        <el-table-column prop="dst_ip" label="目标IP" width="150" />
        <el-table-column prop="dst_port" label="目标端口" width="100" />
        <el-table-column prop="protocol" label="协议" width="100" />
        <el-table-column prop="created_at" label="创建时间" width="180" />
        <el-table-column label="操作" width="100" fixed="right" align="center">
          <template #default="{ row }">
            <el-button type="primary" size="small" @click="showDetails(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="total"
          layout="total, sizes, prev, pager, next, jumper"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>

    <!-- 详情对话框 -->
    <el-dialog v-model="dialogVisible" title="主机行为详情" width="70%" :close-on-click-modal="false">
      <el-descriptions :column="2" border v-if="currentRow">
        <el-descriptions-item label="记录ID">{{ currentRow.id }}</el-descriptions-item>
        <el-descriptions-item label="告警ID">{{ currentRow.alarm_id }}</el-descriptions-item>
        <el-descriptions-item label="告警时间">{{ formatTimestamp(currentRow.alarm_date) }}</el-descriptions-item>
        <el-descriptions-item label="威胁等级">
          <el-tag :type="getSeverityType(currentRow.alarm_severity)">
            {{ getSeverityText(currentRow.alarm_severity) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="告警名称">{{ currentRow.alarm_name }}</el-descriptions-item>
        <el-descriptions-item label="告警类型">{{ getAlarmTypeName() }}</el-descriptions-item>
        <el-descriptions-item label="告警子类型">{{ getAlarmSubtypeName(currentRow.alarm_subtype) }}</el-descriptions-item>
        <el-descriptions-item label="数据来源">{{ getSourceText(currentRow.source) }}</el-descriptions-item>
        <el-descriptions-item label="告警描述" :span="2">{{ currentRow.alarm_description }}</el-descriptions-item>
        
        <el-descriptions-item label="控制规则ID">{{ currentRow.control_rule_id }}</el-descriptions-item>
        <el-descriptions-item label="控制任务ID">{{ currentRow.control_task_id }}</el-descriptions-item>
        <el-descriptions-item label="会话ID">{{ currentRow.session_id }}</el-descriptions-item>
        <el-descriptions-item label="终端ID">{{ currentRow.terminal_id }}</el-descriptions-item>
        <el-descriptions-item label="过程技术ID" :span="2">
          {{ formatJSON(currentRow.procedure_technique_id) }}
        </el-descriptions-item>
        <el-descriptions-item label="源文件路径" :span="2">{{ currentRow.source_file_path }}</el-descriptions-item>
        
        <el-descriptions-item label="源IP">{{ currentRow.src_ip }}</el-descriptions-item>
        <el-descriptions-item label="源端口">{{ currentRow.src_port }}</el-descriptions-item>
        <el-descriptions-item label="目标IP">{{ currentRow.dst_ip }}</el-descriptions-item>
        <el-descriptions-item label="目标端口">{{ currentRow.dst_port }}</el-descriptions-item>
        <el-descriptions-item label="协议">{{ currentRow.protocol }}</el-descriptions-item>
        <el-descriptions-item label="IP版本">{{ currentRow.ip_version }}</el-descriptions-item>
        
        <el-descriptions-item label="主机名">{{ currentRow.host_name }}</el-descriptions-item>
        <el-descriptions-item label="终端IP">{{ currentRow.terminal_ip }}</el-descriptions-item>
        <el-descriptions-item label="用户账号">{{ currentRow.user_account }}</el-descriptions-item>
        <el-descriptions-item label="操作系统">{{ currentRow.terminal_os }}</el-descriptions-item>
        
        <el-descriptions-item label="源进程MD5">{{ currentRow.src_process_md5 }}</el-descriptions-item>
        <el-descriptions-item label="目标进程MD5">{{ currentRow.dst_process_md5 }}</el-descriptions-item>
        <el-descriptions-item label="源进程路径" :span="2">
          <el-input v-model="currentRow.src_process_path" readonly size="small" />
        </el-descriptions-item>
        <el-descriptions-item label="目标进程路径" :span="2">
          <el-input v-model="currentRow.dst_process_path" readonly size="small" />
        </el-descriptions-item>
        <el-descriptions-item label="源进程命令行" :span="2">
          <el-input type="textarea" :rows="2" v-model="currentRow.src_process_cli" readonly />
        </el-descriptions-item>
        <el-descriptions-item label="目标进程命令行" :span="2">
          <el-input type="textarea" :rows="2" v-model="currentRow.dst_process_cli" readonly />
        </el-descriptions-item>
        
        <el-descriptions-item label="注册表键名">{{ currentRow.register_key_name }}</el-descriptions-item>
        <el-descriptions-item label="注册表键值">{{ currentRow.register_key_value }}</el-descriptions-item>
        <el-descriptions-item label="注册表路径" :span="2">{{ currentRow.register_path }}</el-descriptions-item>
        
        <el-descriptions-item label="文件名">{{ currentRow.file_name }}</el-descriptions-item>
        <el-descriptions-item label="文件MD5">{{ currentRow.file_md5 }}</el-descriptions-item>
        <el-descriptions-item label="文件路径" :span="2">
          <el-input v-model="currentRow.file_path" readonly size="small" />
        </el-descriptions-item>
        
        <el-descriptions-item label="额外数据(data)" :span="2">
          <el-input type="textarea" :rows="3" :value="formatJSON(currentRow.data)" readonly />
        </el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ currentRow.created_at }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { getHostBehaviors, getAlarmTypes } from '../api'
import { ElMessage } from 'element-plus'

const tableData = ref([])
const filteredTableData = ref([])
const loading = ref(false)
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)
const dialogVisible = ref(false)
const currentRow = ref(null)
const alarmTypes = ref(null)
const searchForm = ref({
  host_name: '',
  terminal_ip: '',
  user_account: '',
  terminal_os: ''
})

const loadData = async () => {
  loading.value = true
  try {
    const response = await getHostBehaviors(currentPage.value, pageSize.value)
    tableData.value = response.data.data
    total.value = response.data.total
    applyFilter()
  } catch (error) {
    ElMessage.error('加载数据失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const applyFilter = () => {
  let filtered = tableData.value
  
  if (searchForm.value.host_name) {
    filtered = filtered.filter(item => 
      item.host_name && item.host_name.toLowerCase().includes(searchForm.value.host_name.toLowerCase())
    )
  }
  if (searchForm.value.terminal_ip) {
    filtered = filtered.filter(item => 
      item.terminal_ip && item.terminal_ip.includes(searchForm.value.terminal_ip)
    )
  }
  if (searchForm.value.user_account) {
    filtered = filtered.filter(item => 
      item.user_account && item.user_account.toLowerCase().includes(searchForm.value.user_account.toLowerCase())
    )
  }
  if (searchForm.value.terminal_os) {
    filtered = filtered.filter(item => 
      item.terminal_os && item.terminal_os.toLowerCase().includes(searchForm.value.terminal_os.toLowerCase())
    )
  }
  
  filteredTableData.value = filtered
}

const handleSearch = () => {
  applyFilter()
}

const handleReset = () => {
  searchForm.value = {
    host_name: '',
    terminal_ip: '',
    user_account: '',
    terminal_os: ''
  }
  applyFilter()
}

const handleSizeChange = () => {
  loadData()
}

const handleCurrentChange = () => {
  loadData()
}

const showDetails = (row) => {
  currentRow.value = row
  dialogVisible.value = true
}

const getSeverityType = (severity) => {
  const types = { 1: 'success', 2: 'warning', 3: 'danger' }
  return types[severity] || 'success'
}

const getSeverityText = (severity) => {
  const texts = { 1: '低危', 2: '中危', 3: '高危' }
  return texts[severity] || '低危'
}

const formatTimestamp = (timestamp) => {
  if (!timestamp) return '-'
  return new Date(timestamp).toLocaleString('zh-CN')
}

const formatJSON = (value) => {
  if (!value) return '-'
  return JSON.stringify(value, null, 2)
}

const getSourceText = (source) => {
  const texts = { 1: '网络流量', 2: '终端日志', 3: '威胁情报', 4: '其他' }
  return texts[source] || source
}

const getAlarmTypeName = () => {
  return alarmTypes.value?.host_behavior?.name || '主机行为告警'
}

const getAlarmSubtypeName = (code) => {
  if (!code || !alarmTypes.value) return code || '未知'
  // 将数字补零到5位，例如 3001 -> "03001"
  const codeStr = String(code).padStart(5, '0')
  return alarmTypes.value.host_behavior?.subtypes?.[codeStr] || code
}

const loadAlarmTypes = async () => {
  try {
    const response = await getAlarmTypes()
    alarmTypes.value = response.data
  } catch (error) {
    console.error('加载告警类型失败:', error)
  }
}

onMounted(async () => {
  await loadAlarmTypes()
  loadData()
})
</script>

<style scoped>
.page-container {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h2 {
  margin: 0;
}

.search-form {
  margin-bottom: 20px;
  padding: 15px;
  background-color: #f5f7fa;
  border-radius: 4px;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}
</style>

