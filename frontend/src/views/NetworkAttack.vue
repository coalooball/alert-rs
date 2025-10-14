<template>
  <div class="page-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>网络攻击告警</h2>
          <el-button type="primary" @click="loadData" :loading="loading">
            <el-icon><Refresh /></el-icon> 刷新
          </el-button>
        </div>
      </template>

      <el-table :data="tableData" v-loading="loading" stripe border style="width: 100%">
        <el-table-column type="index" label="序号" width="60" />
        <el-table-column prop="alarm_id" label="告警ID" width="280" show-overflow-tooltip />
        <el-table-column prop="alarm_name" label="告警名称" width="200" show-overflow-tooltip />
        <el-table-column prop="alarm_severity" label="严重等级" width="100" align="center">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.alarm_severity)">
              {{ getSeverityText(row.alarm_severity) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="src_ip" label="源IP" width="150" />
        <el-table-column prop="dst_ip" label="目标IP" width="150" />
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
        <el-descriptions-item label="告警ID">{{ currentRow.alarm_id }}</el-descriptions-item>
        <el-descriptions-item label="告警时间">{{ formatTimestamp(currentRow.alarm_date) }}</el-descriptions-item>
        <el-descriptions-item label="告警名称">{{ currentRow.alarm_name }}</el-descriptions-item>
        <el-descriptions-item label="严重等级">
          <el-tag :type="getSeverityType(currentRow.alarm_severity)">
            {{ getSeverityText(currentRow.alarm_severity) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="告警描述" :span="2">{{ currentRow.alarm_description }}</el-descriptions-item>
        <el-descriptions-item label="源IP:端口">{{ currentRow.src_ip }}:{{ currentRow.src_port }}</el-descriptions-item>
        <el-descriptions-item label="目标IP:端口">{{ currentRow.dst_ip }}:{{ currentRow.dst_port }}</el-descriptions-item>
        <el-descriptions-item label="协议">{{ currentRow.protocol }}</el-descriptions-item>
        <el-descriptions-item label="IP版本">{{ currentRow.ip_version }}</el-descriptions-item>
        <el-descriptions-item label="攻击阶段">{{ currentRow.attack_stage }}</el-descriptions-item>
        <el-descriptions-item label="签名ID">{{ currentRow.signature_id }}</el-descriptions-item>
        <el-descriptions-item label="攻击者IP">{{ currentRow.attack_ip }}</el-descriptions-item>
        <el-descriptions-item label="被攻击IP">{{ currentRow.attacked_ip }}</el-descriptions-item>
        <el-descriptions-item label="APT组织">{{ currentRow.apt_group || '未知' }}</el-descriptions-item>
        <el-descriptions-item label="漏洞类型">{{ currentRow.vul_type }}</el-descriptions-item>
        <el-descriptions-item label="CVE ID">{{ currentRow.cve_id }}</el-descriptions-item>
        <el-descriptions-item label="漏洞描述" :span="2">{{ currentRow.vul_desc }}</el-descriptions-item>
        <el-descriptions-item label="攻击载荷" :span="2">
          <el-input type="textarea" :rows="3" v-model="currentRow.attack_payload" readonly />
        </el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { getNetworkAttacks } from '../api'
import { ElMessage } from 'element-plus'

const tableData = ref([])
const loading = ref(false)
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)
const dialogVisible = ref(false)
const currentRow = ref(null)

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
  return new Date(timestamp).toLocaleString('zh-CN')
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

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}
</style>

