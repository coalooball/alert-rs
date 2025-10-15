<template>
  <div class="page-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>恶意样本</h2>
          <el-button type="primary" @click="loadData" :loading="loading">
            <el-icon><Refresh /></el-icon> 刷新
          </el-button>
        </div>
      </template>

      <!-- 搜索表单 -->
      <div class="search-form">
        <el-form :inline="true" :model="searchForm">
          <el-form-item label="样本名称">
            <el-input v-model="searchForm.sample_name" placeholder="请输入样本名称" clearable style="width: 200px" />
          </el-form-item>
          <el-form-item label="文件类型">
            <el-input v-model="searchForm.file_type" placeholder="请输入文件类型" clearable style="width: 120px" />
          </el-form-item>
          <el-form-item label="样本家族">
            <el-input v-model="searchForm.sample_family" placeholder="请输入样本家族" clearable style="width: 150px" />
          </el-form-item>
          <el-form-item label="MD5">
            <el-input v-model="searchForm.md5" placeholder="请输入MD5" clearable style="width: 280px" />
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
        <el-table-column prop="src_ip" label="源IP" width="150" />
        <el-table-column prop="src_port" label="源端口" width="100" />
        <el-table-column prop="dst_ip" label="目标IP" width="150" />
        <el-table-column prop="dst_port" label="目标端口" width="100" />
        <el-table-column prop="protocol" label="协议" width="100" />
        <el-table-column prop="sample_original_name" label="样本名称" width="200" show-overflow-tooltip />
        <el-table-column prop="file_type" label="文件类型" width="120" />
        <el-table-column prop="file_size" label="文件大小" width="120">
          <template #default="{ row }">
            {{ formatFileSize(row.file_size) }}
          </template>
        </el-table-column>
        <el-table-column prop="sample_family" label="样本家族" width="150" show-overflow-tooltip />
        <el-table-column prop="md5" label="MD5" width="280" show-overflow-tooltip />
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
    <el-dialog v-model="dialogVisible" title="样本详情" width="70%" :close-on-click-modal="false">
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
        
        <el-descriptions-item label="样本来源">{{ getSampleSourceText(currentRow.sample_source) }}</el-descriptions-item>
        <el-descriptions-item label="样本原始名称">{{ currentRow.sample_original_name }}</el-descriptions-item>
        <el-descriptions-item label="样本家族">{{ currentRow.sample_family }}</el-descriptions-item>
        <el-descriptions-item label="文件类型">{{ currentRow.file_type }}</el-descriptions-item>
        <el-descriptions-item label="文件大小">{{ formatFileSize(currentRow.file_size) }}</el-descriptions-item>
        <el-descriptions-item label="目标平台">{{ currentRow.target_platform }}</el-descriptions-item>
        <el-descriptions-item label="编程语言">{{ currentRow.language }}</el-descriptions-item>
        <el-descriptions-item label="APT组织">{{ currentRow.apt_group }}</el-descriptions-item>
        
        <el-descriptions-item label="MD5" :span="2">
          <el-input v-model="currentRow.md5" readonly size="small" />
        </el-descriptions-item>
        <el-descriptions-item label="SHA1" :span="2">
          <el-input v-model="currentRow.sha1" readonly size="small" />
        </el-descriptions-item>
        <el-descriptions-item label="SHA256" :span="2">
          <el-input v-model="currentRow.sha256" readonly size="small" />
        </el-descriptions-item>
        <el-descriptions-item label="SHA512" :span="2">
          <el-input v-model="currentRow.sha512" readonly size="small" />
        </el-descriptions-item>
        <el-descriptions-item label="SSDEEP" :span="2">
          <el-input v-model="currentRow.ssdeep" readonly size="small" />
        </el-descriptions-item>
        
        <el-descriptions-item label="规则">{{ currentRow.rule }}</el-descriptions-item>
        <el-descriptions-item label="目标内容">{{ currentRow.target_content }}</el-descriptions-item>
        <el-descriptions-item label="编译时间">{{ formatTimestamp(currentRow.compile_date) }}</el-descriptions-item>
        <el-descriptions-item label="最后分析时间">{{ formatTimestamp(currentRow.last_analy_date) }}</el-descriptions-item>
        <el-descriptions-item label="样本告警引擎" :span="2">
          {{ formatJSON(currentRow.sample_alarm_engine) }}
        </el-descriptions-item>
        
        <el-descriptions-item label="样本描述" :span="2">{{ currentRow.sample_description }}</el-descriptions-item>
        <el-descriptions-item label="告警详情" :span="2">
          <el-input type="textarea" :rows="3" v-model="currentRow.sample_alarm_detail" readonly />
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
import { getMaliciousSamples, getAlarmTypes } from '../api'
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
  sample_name: '',
  file_type: '',
  sample_family: '',
  md5: ''
})

const loadData = async () => {
  loading.value = true
  try {
    const response = await getMaliciousSamples(currentPage.value, pageSize.value)
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
  
  if (searchForm.value.sample_name) {
    filtered = filtered.filter(item => 
      item.sample_original_name && item.sample_original_name.toLowerCase().includes(searchForm.value.sample_name.toLowerCase())
    )
  }
  if (searchForm.value.file_type) {
    filtered = filtered.filter(item => 
      item.file_type && item.file_type.toLowerCase().includes(searchForm.value.file_type.toLowerCase())
    )
  }
  if (searchForm.value.sample_family) {
    filtered = filtered.filter(item => 
      item.sample_family && item.sample_family.toLowerCase().includes(searchForm.value.sample_family.toLowerCase())
    )
  }
  if (searchForm.value.md5) {
    filtered = filtered.filter(item => 
      item.md5 && item.md5.toLowerCase().includes(searchForm.value.md5.toLowerCase())
    )
  }
  
  filteredTableData.value = filtered
}

const handleSearch = () => {
  applyFilter()
}

const handleReset = () => {
  searchForm.value = {
    sample_name: '',
    file_type: '',
    sample_family: '',
    md5: ''
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

const getSampleSourceText = (source) => {
  const texts = { 1: '网络捕获', 2: '本地检测', 3: '邮件附件', 4: '其他' }
  return texts[source] || '未知'
}

const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
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
  return alarmTypes.value?.malicious_sample?.name || '恶意样本告警'
}

const getAlarmSubtypeName = (code) => {
  if (!code || !alarmTypes.value) return code || '未知'
  // 将数字补零到5位，例如 2001 -> "02001"
  const codeStr = String(code).padStart(5, '0')
  return alarmTypes.value.malicious_sample?.subtypes?.[codeStr] || code
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

