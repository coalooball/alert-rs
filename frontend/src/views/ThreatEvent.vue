<template>
  <div class="page-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>威胁事件</h2>
          <el-button type="primary" @click="loadData" :loading="loading">
            <el-icon><Refresh /></el-icon> 刷新
          </el-button>
        </div>
      </template>

      <!-- 搜索表单 -->
      <div class="search-form">
        <el-form :inline="true" :model="searchForm">
          <el-form-item label="事件名称">
            <el-input v-model="searchForm.name" placeholder="请输入事件名称" clearable style="width: 200px" />
          </el-form-item>
          <el-form-item label="攻击者">
            <el-input v-model="searchForm.attacker" placeholder="请输入攻击者" clearable style="width: 150px" />
          </el-form-item>
          <el-form-item label="受害者">
            <el-input v-model="searchForm.victimer" placeholder="请输入受害者" clearable style="width: 150px" />
          </el-form-item>
          <el-form-item label="优先级">
            <el-select v-model="searchForm.priority" placeholder="选择优先级" clearable style="width: 120px">
              <el-option label="高" value="高" />
              <el-option label="中" value="中" />
              <el-option label="低" value="低" />
            </el-select>
          </el-form-item>
          <el-form-item label="等级">
            <el-select v-model="searchForm.severity" placeholder="选择等级" clearable style="width: 120px">
              <el-option label="严重" value="严重" />
              <el-option label="高危" value="高危" />
              <el-option label="中危" value="中危" />
              <el-option label="低危" value="低危" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="handleSearch">搜索</el-button>
            <el-button @click="handleReset">重置</el-button>
          </el-form-item>
        </el-form>
      </div>

      <el-table :data="filteredTableData" v-loading="loading" stripe border style="width: 100%">
        <el-table-column type="index" label="序号" width="60" />
        <el-table-column prop="event_id" label="事件ID" width="100" />
        <el-table-column prop="system_code" label="系统编号" width="150" show-overflow-tooltip />
        <el-table-column prop="name" label="事件名称" width="200" show-overflow-tooltip />
        <el-table-column prop="event_type" label="事件类型" width="120" />
        <el-table-column prop="attacker" label="攻击者" width="150" show-overflow-tooltip />
        <el-table-column prop="victimer" label="受害者" width="150" show-overflow-tooltip />
        <el-table-column prop="priority" label="优先级" width="100" align="center">
          <template #default="{ row }">
            <el-tag :type="getPriorityType(row.priority)">
              {{ row.priority || '-' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="等级" width="100" align="center">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)">
              {{ row.severity || '-' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="dispose_status" label="处置状态" width="120" align="center">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.dispose_status)">
              {{ row.dispose_status || '-' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="found_time" label="监测时间" width="180" />
        <el-table-column prop="created_at" label="创建时间" width="180" />
        <el-table-column label="操作" width="100" fixed="right" align="center">
          <template #default="{ row }">
            <el-button type="primary" size="small" @click="showReview(row)">审核</el-button>
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

    <!-- 审核对话框 -->
    <el-dialog 
      v-model="dialogVisible" 
      title="威胁事件审核" 
      width="80%" 
      :close-on-click-modal="false"
    >
      <el-form :model="formData" label-width="150px" v-if="formData">
        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item label="记录ID">
              <el-input v-model="formData.id" disabled />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="事件ID">
              <el-input v-model.number="formData.event_id" />
            </el-form-item>
          </el-col>
          
          <el-col :span="12">
            <el-form-item label="系统编号">
              <el-input v-model="formData.system_code" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="事件类型">
              <el-input v-model="formData.event_type" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="事件名称">
              <el-input v-model="formData.name" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="事件描述">
              <el-input type="textarea" :rows="3" v-model="formData.description" />
            </el-form-item>
          </el-col>
          
          <el-col :span="12">
            <el-form-item label="攻击者">
              <el-input v-model="formData.attacker" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="受害者">
              <el-input v-model="formData.victimer" />
            </el-form-item>
          </el-col>
          
          <el-col :span="12">
            <el-form-item label="优先级">
              <el-select v-model="formData.priority" style="width: 100%">
                <el-option label="高" value="高" />
                <el-option label="中" value="中" />
                <el-option label="低" value="低" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="等级">
              <el-select v-model="formData.severity" style="width: 100%">
                <el-option label="严重" value="严重" />
                <el-option label="高危" value="高危" />
                <el-option label="中危" value="中危" />
                <el-option label="低危" value="低危" />
              </el-select>
            </el-form-item>
          </el-col>
          
          <el-col :span="12">
            <el-form-item label="处置状态">
              <el-tag :type="getStatusType(formData.dispose_status)">
                {{ formData.dispose_status || '未审核' }}
              </el-tag>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="数据来源">
              <el-input v-model="formData.source" />
            </el-form-item>
          </el-col>
          
          <el-col :span="12">
            <el-form-item label="事件开始时间">
              <el-input v-model="formData.start_time" placeholder="YYYY-MM-DD HH:mm:ss" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="事件结束时间">
              <el-input v-model="formData.end_time" placeholder="YYYY-MM-DD HH:mm:ss" />
            </el-form-item>
          </el-col>
          
          <el-col :span="12">
            <el-form-item label="监测时间">
              <el-input v-model="formData.found_time" placeholder="YYYY-MM-DD HH:mm:ss" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="首次发现时间">
              <el-input v-model="formData.first_found_time" placeholder="YYYY-MM-DD HH:mm:ss" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="MITRE ATT&CK ID">
              <el-input v-model="formData.mitre_technique_id" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="技战法列表">
              <el-input v-model="formData.attsck_list" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="攻击工具">
              <el-input v-model="formData.attack_tool" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="应用程序">
              <el-input v-model="formData.app" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="影响评估">
              <el-input type="textarea" :rows="2" v-model="formData.impact_assessment" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="威胁主体">
              <el-input type="textarea" :rows="3" v-model="formData.threat_actor" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="威胁目标">
              <el-input type="textarea" :rows="3" v-model="formData.org" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="收敛告警列表">
              <el-input type="textarea" :rows="3" v-model="formData.merge_alerts" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="攻击者IP列表">
              <el-input type="textarea" :rows="2" v-model="formData.attack_asset_ip" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="受害者IP列表">
              <el-input type="textarea" :rows="2" v-model="formData.victim_asset_ip" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="攻击者端口列表">
              <el-input type="textarea" :rows="2" v-model="formData.attack_asset_ip_port" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="受害者端口列表">
              <el-input type="textarea" :rows="2" v-model="formData.victim_asset_ip_port" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="攻击者域名">
              <el-input type="textarea" :rows="2" v-model="formData.attack_asset_domain" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="受害者域名">
              <el-input type="textarea" :rows="2" v-model="formData.victim_asset_domain" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="攻击URL">
              <el-input type="textarea" :rows="2" v-model="formData.attack_url" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="受害者URL">
              <el-input type="textarea" :rows="2" v-model="formData.victim_url" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="恶意代码">
              <el-input type="textarea" :rows="2" v-model="formData.attack_malware" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="恶意样本">
              <el-input type="textarea" :rows="2" v-model="formData.attack_malware_sample" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="样本家族">
              <el-input type="textarea" :rows="2" v-model="formData.attack_malware_sample_family" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="攻击者邮箱">
              <el-input type="textarea" :rows="2" v-model="formData.attack_email_address" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="受害者邮箱">
              <el-input type="textarea" :rows="2" v-model="formData.victim_email_address" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="攻击邮件">
              <el-input type="textarea" :rows="2" v-model="formData.attack_email" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="受害者邮件">
              <el-input type="textarea" :rows="2" v-model="formData.victim_email" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="攻击软件">
              <el-input type="textarea" :rows="2" v-model="formData.attack_software" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="受害者软件">
              <el-input type="textarea" :rows="2" v-model="formData.victim_software" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="攻击漏洞">
              <el-input type="textarea" :rows="2" v-model="formData.attack_vulnerability" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="攻击证书">
              <el-input type="textarea" :rows="2" v-model="formData.attack_certificate" />
            </el-form-item>
          </el-col>
          
          <el-col :span="24">
            <el-form-item label="受害者证书">
              <el-input type="textarea" :rows="2" v-model="formData.victim_certificate" />
            </el-form-item>
          </el-col>
          
          <el-col :span="12">
            <el-form-item label="创建时间">
              <el-input v-model="formData.created_at" disabled />
            </el-form-item>
          </el-col>
        </el-row>
      </el-form>
      
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="dialogVisible = false">取消</el-button>
          <el-button type="primary" @click="handleSave" :loading="saving">保存</el-button>
          <el-button 
            type="success" 
            @click="handleSubmit" 
            :loading="submitting"
            :disabled="isReviewed"
          >
            {{ isReviewed ? '已审核' : '提交' }}
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { getThreatEvents, updateThreatEvent } from '../api'
import { ElMessage } from 'element-plus'

const tableData = ref([])
const filteredTableData = ref([])
const loading = ref(false)
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)
const dialogVisible = ref(false)
const formData = ref(null)
const saving = ref(false)
const submitting = ref(false)
const searchForm = ref({
  name: '',
  attacker: '',
  victimer: '',
  priority: '',
  severity: ''
})

const isReviewed = computed(() => {
  return formData.value?.dispose_status === '已审核'
})

const loadData = async () => {
  loading.value = true
  try {
    const response = await getThreatEvents(currentPage.value, pageSize.value)
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
  
  if (searchForm.value.name) {
    filtered = filtered.filter(item => 
      item.name && item.name.toLowerCase().includes(searchForm.value.name.toLowerCase())
    )
  }
  if (searchForm.value.attacker) {
    filtered = filtered.filter(item => 
      item.attacker && item.attacker.toLowerCase().includes(searchForm.value.attacker.toLowerCase())
    )
  }
  if (searchForm.value.victimer) {
    filtered = filtered.filter(item => 
      item.victimer && item.victimer.toLowerCase().includes(searchForm.value.victimer.toLowerCase())
    )
  }
  if (searchForm.value.priority) {
    filtered = filtered.filter(item => item.priority === searchForm.value.priority)
  }
  if (searchForm.value.severity) {
    filtered = filtered.filter(item => item.severity === searchForm.value.severity)
  }
  
  filteredTableData.value = filtered
}

const handleSearch = () => {
  applyFilter()
}

const handleReset = () => {
  searchForm.value = {
    name: '',
    attacker: '',
    victimer: '',
    priority: '',
    severity: ''
  }
  applyFilter()
}

const handleSizeChange = () => {
  loadData()
}

const handleCurrentChange = () => {
  loadData()
}

const showReview = (row) => {
  // 深拷贝当前行数据到表单
  formData.value = {
    ...row,
    // 将 JSON 对象转换为字符串以便编辑
    threat_actor: formatJSON(row.threat_actor),
    org: formatJSON(row.org),
    merge_alerts: formatJSON(row.merge_alerts),
    attack_asset_ip: formatJSON(row.attack_asset_ip),
    victim_asset_ip: formatJSON(row.victim_asset_ip),
    attack_asset_ip_port: formatJSON(row.attack_asset_ip_port),
    victim_asset_ip_port: formatJSON(row.victim_asset_ip_port),
    attack_asset_domain: formatJSON(row.attack_asset_domain),
    victim_asset_domain: formatJSON(row.victim_asset_domain),
    attack_url: formatJSON(row.attack_url),
    victim_url: formatJSON(row.victim_url),
    attack_malware: formatJSON(row.attack_malware),
    attack_malware_sample: formatJSON(row.attack_malware_sample),
    attack_malware_sample_family: formatJSON(row.attack_malware_sample_family),
    attack_email_address: formatJSON(row.attack_email_address),
    victim_email_address: formatJSON(row.victim_email_address),
    attack_email: formatJSON(row.attack_email),
    victim_email: formatJSON(row.victim_email),
    attack_software: formatJSON(row.attack_software),
    victim_software: formatJSON(row.victim_software),
    attack_vulnerability: formatJSON(row.attack_vulnerability),
    attack_certificate: formatJSON(row.attack_certificate),
    victim_certificate: formatJSON(row.victim_certificate),
    start_time: formatTimeForEdit(row.start_time),
    end_time: formatTimeForEdit(row.end_time),
    found_time: formatTimeForEdit(row.found_time),
    first_found_time: formatTimeForEdit(row.first_found_time)
  }
  dialogVisible.value = true
}

const handleSave = async () => {
  saving.value = true
  try {
    await saveEvent()
    ElMessage.success('保存成功')
  } catch (error) {
    ElMessage.error('保存失败: ' + error.message)
  } finally {
    saving.value = false
  }
}

const handleSubmit = async () => {
  submitting.value = true
  try {
    // 设置状态为已审核
    formData.value.dispose_status = '已审核'
    await saveEvent()
    ElMessage.success('提交成功')
    dialogVisible.value = false
    loadData()
  } catch (error) {
    ElMessage.error('提交失败: ' + error.message)
  } finally {
    submitting.value = false
  }
}

const saveEvent = async () => {
  // 准备要发送的数据，将 JSON 字符串转回对象
  const dataToSend = {
    ...formData.value,
    threat_actor: parseJSONField(formData.value.threat_actor),
    org: parseJSONField(formData.value.org),
    merge_alerts: parseJSONField(formData.value.merge_alerts),
    attack_asset_ip: parseJSONField(formData.value.attack_asset_ip),
    victim_asset_ip: parseJSONField(formData.value.victim_asset_ip),
    attack_asset_ip_port: parseJSONField(formData.value.attack_asset_ip_port),
    victim_asset_ip_port: parseJSONField(formData.value.victim_asset_ip_port),
    attack_asset_domain: parseJSONField(formData.value.attack_asset_domain),
    victim_asset_domain: parseJSONField(formData.value.victim_asset_domain),
    attack_url: parseJSONField(formData.value.attack_url),
    victim_url: parseJSONField(formData.value.victim_url),
    attack_malware: parseJSONField(formData.value.attack_malware),
    attack_malware_sample: parseJSONField(formData.value.attack_malware_sample),
    attack_malware_sample_family: parseJSONField(formData.value.attack_malware_sample_family),
    attack_email_address: parseJSONField(formData.value.attack_email_address),
    victim_email_address: parseJSONField(formData.value.victim_email_address),
    attack_email: parseJSONField(formData.value.attack_email),
    victim_email: parseJSONField(formData.value.victim_email),
    attack_software: parseJSONField(formData.value.attack_software),
    victim_software: parseJSONField(formData.value.victim_software),
    attack_vulnerability: parseJSONField(formData.value.attack_vulnerability),
    attack_certificate: parseJSONField(formData.value.attack_certificate),
    victim_certificate: parseJSONField(formData.value.victim_certificate),
    start_time: parseTimeForSave(formData.value.start_time),
    end_time: parseTimeForSave(formData.value.end_time),
    found_time: parseTimeForSave(formData.value.found_time),
    first_found_time: parseTimeForSave(formData.value.first_found_time)
  }
  
  // 删除不应该发送的字段
  delete dataToSend.id
  delete dataToSend.created_at
  
  await updateThreatEvent(formData.value.id, dataToSend)
}

const parseJSONField = (value) => {
  if (!value || value === '-') return null
  if (typeof value === 'object') return value
  try {
    return JSON.parse(value)
  } catch {
    return value
  }
}

const parseTimeForSave = (value) => {
  if (!value || value === '-') return null
  // 将本地时间字符串转换为 UTC ISO 格式
  try {
    return new Date(value).toISOString()
  } catch {
    return null
  }
}

const getPriorityType = (priority) => {
  const types = { '高': 'danger', '中': 'warning', '低': 'success' }
  return types[priority] || 'info'
}

const getSeverityType = (severity) => {
  const types = { '严重': 'danger', '高危': 'danger', '中危': 'warning', '低危': 'success' }
  return types[severity] || 'info'
}

const getStatusType = (status) => {
  const types = { '未审核': 'warning', '已审核': 'success' }
  return types[status] || 'info'
}

const formatTime = (time) => {
  if (!time) return '-'
  return new Date(time).toLocaleString('zh-CN')
}

const formatTimeForEdit = (time) => {
  if (!time) return ''
  const date = new Date(time)
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  const hour = String(date.getHours()).padStart(2, '0')
  const minute = String(date.getMinutes()).padStart(2, '0')
  const second = String(date.getSeconds()).padStart(2, '0')
  return `${year}-${month}-${day} ${hour}:${minute}:${second}`
}

const formatJSON = (value) => {
  if (!value) return ''
  if (typeof value === 'string') return value
  return JSON.stringify(value, null, 2)
}

const parseArray = (value) => {
  if (!value) return []
  if (Array.isArray(value)) return value
  try {
    const parsed = JSON.parse(value)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

onMounted(() => {
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
