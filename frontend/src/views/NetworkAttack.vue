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

      <!-- 搜索表单 -->
      <div class="search-form">
        <el-form :inline="true" :model="searchForm">
          <el-form-item label="源IP">
            <el-input v-model="searchForm.src_ip" placeholder="请输入源IP" clearable style="width: 150px" />
          </el-form-item>
          <el-form-item label="源端口">
            <el-input v-model="searchForm.src_port" placeholder="请输入源端口" clearable style="width: 120px" />
          </el-form-item>
          <el-form-item label="目标IP">
            <el-input v-model="searchForm.dst_ip" placeholder="请输入目标IP" clearable style="width: 150px" />
          </el-form-item>
          <el-form-item label="目标端口">
            <el-input v-model="searchForm.dst_port" placeholder="请输入目标端口" clearable style="width: 120px" />
          </el-form-item>
          <el-form-item label="协议">
            <el-input v-model="searchForm.protocol" placeholder="请输入协议" clearable style="width: 100px" />
          </el-form-item>
          <el-form-item label="标签">
            <el-select
              v-model="searchForm.tags"
              multiple
              filterable
              placeholder="选择或搜索标签"
              style="width: 200px"
              clearable
            >
              <el-option
                v-for="tag in allTags"
                :key="tag.id"
                :label="tag.name"
                :value="tag.name"
              />
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
            {{ row.alarm_subtype_name || getAlarmSubtypeName(row.alarm_subtype) }}
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
        <el-table-column label="标签" width="200" show-overflow-tooltip>
          <template #default="{ row }">
            <div v-if="row.tags && row.tags.length > 0" style="display: flex; flex-wrap: wrap; gap: 4px;">
              <el-tag v-for="tag in row.tags" :key="tag.id" size="small" :color="tag.color" style="margin: 2px;">
                {{ tag.name }}
              </el-tag>
            </div>
            <span v-else style="color: #909399; font-size: 12px;">无标签</span>
          </template>
        </el-table-column>
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
      <el-tabs v-model="activeTab" v-if="currentRow">
        <!-- 告警详情标签页 -->
        <el-tab-pane label="告警详情" name="detail">
          <el-descriptions :column="2" border>
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
            <el-descriptions-item label="告警子类型">{{ currentRow.alarm_subtype_name || getAlarmSubtypeName(currentRow.alarm_subtype) }}</el-descriptions-item>
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
            
            <el-descriptions-item label="标签" :span="2">
              <div style="display: flex; flex-wrap: wrap; gap: 8px; align-items: center;">
                <el-tag
                  v-for="tag in alertTags"
                  :key="tag.id"
                  :color="tag.color"
                  closable
                  @close="handleRemoveTag(tag.id)"
                  style="margin: 2px;"
                >
                  {{ tag.name }}
                </el-tag>
                <el-button type="primary" size="small" :icon="Plus" @click="openTagDialog">添加标签</el-button>
              </div>
            </el-descriptions-item>
          </el-descriptions>
        </el-tab-pane>

        <!-- 原始告警标签页 -->
        <el-tab-pane label="原始告警" name="raw">
          <div v-loading="rawAlertsLoading">
            <el-alert
              v-if="rawAlerts.length === 0 && !rawAlertsLoading"
              title="暂无原始告警数据"
              type="info"
              :closable="false"
              style="margin-bottom: 20px"
            />
            <el-collapse v-model="activeRawAlert" accordion v-if="rawAlerts.length > 0">
              <el-collapse-item 
                v-for="(rawAlert, index) in rawAlerts" 
                :key="rawAlert.id" 
                :name="index"
                :title="`原始告警 ${index + 1} - ${rawAlert.alarm_name || '未命名'}`"
              >
                <el-descriptions :column="2" border size="small">
                  <el-descriptions-item label="告警ID">{{ rawAlert.alarm_id }}</el-descriptions-item>
                  <el-descriptions-item label="告警时间">{{ formatTimestamp(rawAlert.alarm_date) }}</el-descriptions-item>
                  <el-descriptions-item label="威胁等级">
                    <el-tag :type="getSeverityType(rawAlert.alarm_severity)" size="small">
                      {{ getSeverityText(rawAlert.alarm_severity) }}
                    </el-tag>
                  </el-descriptions-item>
                  <el-descriptions-item label="告警名称">{{ rawAlert.alarm_name }}</el-descriptions-item>
                  <el-descriptions-item label="攻击阶段">{{ rawAlert.attack_stage }}</el-descriptions-item>
                  <el-descriptions-item label="漏洞类型">{{ rawAlert.vul_type }}</el-descriptions-item>
                  <el-descriptions-item label="CVE编号">{{ rawAlert.cve_id }}</el-descriptions-item>
                  <el-descriptions-item label="签名ID">{{ rawAlert.signature_id }}</el-descriptions-item>
                  <el-descriptions-item label="源IP">{{ rawAlert.src_ip }}</el-descriptions-item>
                  <el-descriptions-item label="源端口">{{ rawAlert.src_port }}</el-descriptions-item>
                  <el-descriptions-item label="目标IP">{{ rawAlert.dst_ip }}</el-descriptions-item>
                  <el-descriptions-item label="目标端口">{{ rawAlert.dst_port }}</el-descriptions-item>
                  <el-descriptions-item label="协议">{{ rawAlert.protocol }}</el-descriptions-item>
                  <el-descriptions-item label="创建时间">{{ rawAlert.created_at }}</el-descriptions-item>
                  <el-descriptions-item label="告警描述" :span="2">{{ rawAlert.alarm_description }}</el-descriptions-item>
                </el-descriptions>
              </el-collapse-item>
            </el-collapse>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-dialog>

    <!-- 添加标签对话框 -->
    <el-dialog v-model="tagDialogVisible" title="添加标签" width="500px">
      <el-select
        v-model="selectedTagIds"
        multiple
        placeholder="请选择标签"
        style="width: 100%"
        @change="handleTagSelectionChange"
      >
        <el-option
          v-for="tag in allTags"
          :key="tag.id"
          :label="tag.name"
          :value="tag.id"
        >
          <span style="float: left">{{ tag.name }}</span>
          <span style="float: right; color: var(--el-text-color-secondary); font-size: 13px">
            {{ tag.category }}
          </span>
        </el-option>
      </el-select>
      <template #footer>
        <el-button @click="tagDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleConfirmTags">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Refresh, Plus } from '@element-plus/icons-vue'
import { getNetworkAttacks, getAlarmTypes, getRawNetworkAttacksByConvergedId, getAllTags, getAlertTags, addAlertTag, removeAlertTag } from '../api'
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
const activeTab = ref('detail')
const rawAlerts = ref([])
const rawAlertsLoading = ref(false)
const activeRawAlert = ref(0)
const searchForm = ref({
  src_ip: '',
  src_port: '',
  dst_ip: '',
  dst_port: '',
  protocol: '',
  tags: []
})
const allTags = ref([])
const alertTags = ref([])
const tagDialogVisible = ref(false)
const selectedTagIds = ref([])

const loadData = async () => {
  loading.value = true
  try {
    const response = await getNetworkAttacks(currentPage.value, pageSize.value)
    tableData.value = response.data.data
    total.value = response.data.total
    
    // 加载每个告警的标签
    await loadTagsForAlerts()
    
    applyFilter()
  } catch (error) {
    ElMessage.error('加载数据失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const loadTagsForAlerts = async () => {
  for (const alert of tableData.value) {
    try {
      const response = await getAlertTags('network_attack', alert.id)
      alert.tags = response.data.data || []
    } catch (error) {
      console.error(`加载告警 ${alert.id} 标签失败:`, error)
      alert.tags = []
    }
  }
}

const applyFilter = () => {
  let filtered = tableData.value
  
  if (searchForm.value.src_ip) {
    filtered = filtered.filter(item => 
      item.src_ip && item.src_ip.includes(searchForm.value.src_ip)
    )
  }
  if (searchForm.value.src_port) {
    filtered = filtered.filter(item => 
      item.src_port && String(item.src_port).includes(searchForm.value.src_port)
    )
  }
  if (searchForm.value.dst_ip) {
    filtered = filtered.filter(item => 
      item.dst_ip && item.dst_ip.includes(searchForm.value.dst_ip)
    )
  }
  if (searchForm.value.dst_port) {
    filtered = filtered.filter(item => 
      item.dst_port && String(item.dst_port).includes(searchForm.value.dst_port)
    )
  }
  if (searchForm.value.protocol) {
    filtered = filtered.filter(item => 
      item.protocol && item.protocol.toLowerCase().includes(searchForm.value.protocol.toLowerCase())
    )
  }
  if (searchForm.value.tags && searchForm.value.tags.length > 0) {
    filtered = filtered.filter(item => 
      item.tags && item.tags.some(tag => 
        searchForm.value.tags.some(searchTag => 
          tag.name.toLowerCase().includes(searchTag.toLowerCase())
        )
      )
    )
  }
  
  filteredTableData.value = filtered
}

const handleSearch = () => {
  applyFilter()
}

const handleReset = () => {
  searchForm.value = {
    src_ip: '',
    src_port: '',
    dst_ip: '',
    dst_port: '',
    protocol: '',
    tags: []
  }
  applyFilter()
}

const handleSizeChange = () => {
  loadData()
}

const handleCurrentChange = () => {
  loadData()
}

const showDetails = async (row) => {
  currentRow.value = row
  dialogVisible.value = true
  activeTab.value = 'detail'
  rawAlerts.value = []
  
  // 加载原始告警数据
  loadRawAlerts(row.id)
  
  // 加载告警的标签
  loadCurrentAlertTags()
}

const loadRawAlerts = async (convergedAlertId) => {
  rawAlertsLoading.value = true
  try {
    const response = await getRawNetworkAttacksByConvergedId(convergedAlertId)
    rawAlerts.value = response.data || []
  } catch (error) {
    console.error('加载原始告警失败:', error)
    rawAlerts.value = []
    // 只在真正出错时提示，空数组不提示
    if (error.response && error.response.status !== 200) {
      ElMessage.error('加载原始告警失败')
    }
  } finally {
    rawAlertsLoading.value = false
  }
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
  if (code === undefined || code === null || !alarmTypes.value) return code ?? '未知'
  const key = String(code)
  return alarmTypes.value.network_attack?.subtypes?.[key] || code
}

const loadAlarmTypes = async () => {
  try {
    const response = await getAlarmTypes()
    alarmTypes.value = response.data
  } catch (error) {
    console.error('加载告警类型失败:', error)
  }
}

const loadAllTags = async () => {
  try {
    const response = await getAllTags()
    allTags.value = response.data.data || []
  } catch (error) {
    console.error('加载标签列表失败:', error)
  }
}

const loadCurrentAlertTags = async () => {
  if (!currentRow.value) return
  try {
    const response = await getAlertTags('network_attack', currentRow.value.id)
    alertTags.value = response.data.data || []
  } catch (error) {
    console.error('加载告警标签失败:', error)
    alertTags.value = []
  }
}

const openTagDialog = () => {
  selectedTagIds.value = alertTags.value.map(tag => tag.id)
  tagDialogVisible.value = true
}

const handleAddTag = async (tagId) => {
  try {
    await addAlertTag('network_attack', currentRow.value.id, tagId)
    ElMessage.success('添加标签成功')
    await loadCurrentAlertTags()
    await loadTagsForAlerts()
    applyFilter()
  } catch (error) {
    ElMessage.error('添加标签失败: ' + error.message)
  }
}

const handleRemoveTag = async (tagId) => {
  try {
    await removeAlertTag('network_attack', currentRow.value.id, tagId)
    ElMessage.success('移除标签成功')
    await loadCurrentAlertTags()
    await loadTagsForAlerts()
    applyFilter()
  } catch (error) {
    ElMessage.error('移除标签失败: ' + error.message)
  }
}

const handleTagSelectionChange = (value) => {
  // 处理标签选择变化
}

const handleConfirmTags = async () => {
  const currentTagIds = alertTags.value.map(tag => tag.id)
  const addedTagIds = selectedTagIds.value.filter(id => !currentTagIds.includes(id))
  const removedTagIds = currentTagIds.filter(id => !selectedTagIds.value.includes(id))

  try {
    // 添加新标签
    for (const tagId of addedTagIds) {
      await addAlertTag('network_attack', currentRow.value.id, tagId)
    }

    // 移除取消选择的标签
    for (const tagId of removedTagIds) {
      await removeAlertTag('network_attack', currentRow.value.id, tagId)
    }

    ElMessage.success('标签更新成功')
    tagDialogVisible.value = false
    await loadCurrentAlertTags()
    await loadTagsForAlerts()
    applyFilter()
  } catch (error) {
    ElMessage.error('标签更新失败: ' + error.message)
  }
}

onMounted(async () => {
  await loadAlarmTypes()
  await loadAllTags()
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

