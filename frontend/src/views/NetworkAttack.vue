<template>
  <div class="page-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>精控流量</h2>
          <el-button type="primary" @click="loadData" :loading="loading">
            <el-icon><Refresh /></el-icon> 刷新
          </el-button>
        </div>
      </template>

      <el-table :data="tableData" v-loading="loading" stripe border style="width: 100%">
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
        <el-table-column prop="attack_stage" label="攻击阶段" width="150" show-overflow-tooltip />
        <el-table-column prop="vul_type" label="漏洞类型" width="150" show-overflow-tooltip />
        <el-table-column prop="cve_id" label="CVE编号" width="180" show-overflow-tooltip />
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
    <el-dialog v-model="dialogVisible" title="告警详情" width="70%" :close-on-click-modal="false">
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
        
        <el-descriptions-item label="攻击阶段">{{ currentRow.attack_stage }}</el-descriptions-item>
        <el-descriptions-item label="签名ID">{{ currentRow.signature_id }}</el-descriptions-item>
        <el-descriptions-item label="攻击者IP">{{ currentRow.attack_ip }}</el-descriptions-item>
        <el-descriptions-item label="被攻击IP">{{ currentRow.attacked_ip }}</el-descriptions-item>
        <el-descriptions-item label="APT组织">{{ currentRow.apt_group }}</el-descriptions-item>
        <el-descriptions-item label="漏洞类型">{{ currentRow.vul_type }}</el-descriptions-item>
        <el-descriptions-item label="CVE ID">{{ currentRow.cve_id }}</el-descriptions-item>
        <el-descriptions-item label="漏洞描述" :span="2">{{ currentRow.vul_desc }}</el-descriptions-item>
        <el-descriptions-item label="攻击载荷" :span="2">
          <el-input type="textarea" :rows="3" v-model="currentRow.attack_payload" readonly />
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
import { getNetworkAttacks, getAlarmTypes } from '../api'
import { ElMessage } from 'element-plus'

const tableData = ref([])
const loading = ref(false)
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)
const dialogVisible = ref(false)
const currentRow = ref(null)
const alarmTypes = ref(null)

const loadData = async () => {
  loading.value = true
  try {
    const response = await getNetworkAttacks(currentPage.value, pageSize.value)
    tableData.value = response.data.data
    total.value = response.data.total
  } catch (error) {
    ElMessage.error('加载数据失败: ' + error.message)
  } finally {
    loading.value = false
  }
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
  return alarmTypes.value?.network_attack?.name || '网络攻击告警'
}

const getAlarmSubtypeName = (code) => {
  if (!code || !alarmTypes.value) return code || '未知'
  // 将数字补零到5位，例如 1001 -> "01001"
  const codeStr = String(code).padStart(5, '0')
  return alarmTypes.value.network_attack?.subtypes?.[codeStr] || code
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

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}
</style>

