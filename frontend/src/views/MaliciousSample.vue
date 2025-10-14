<template>
  <div class="page-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>🟠 恶意样本告警</h2>
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
        <el-descriptions-item label="告警ID">{{ currentRow.alarm_id }}</el-descriptions-item>
        <el-descriptions-item label="告警时间">{{ formatTimestamp(currentRow.alarm_date) }}</el-descriptions-item>
        <el-descriptions-item label="告警名称">{{ currentRow.alarm_name }}</el-descriptions-item>
        <el-descriptions-item label="严重等级">
          <el-tag :type="getSeverityType(currentRow.alarm_severity)">
            {{ getSeverityText(currentRow.alarm_severity) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="告警描述" :span="2">{{ currentRow.alarm_description }}</el-descriptions-item>
        
        <el-descriptions-item label="样本原始名称">{{ currentRow.sample_original_name }}</el-descriptions-item>
        <el-descriptions-item label="样本家族">{{ currentRow.sample_family }}</el-descriptions-item>
        <el-descriptions-item label="文件类型">{{ currentRow.file_type }}</el-descriptions-item>
        <el-descriptions-item label="文件大小">{{ formatFileSize(currentRow.file_size) }}</el-descriptions-item>
        <el-descriptions-item label="目标平台">{{ currentRow.target_platform }}</el-descriptions-item>
        <el-descriptions-item label="编程语言">{{ currentRow.language }}</el-descriptions-item>
        
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
        
        <el-descriptions-item label="APT组织">{{ currentRow.apt_group || '未知' }}</el-descriptions-item>
        <el-descriptions-item label="样本来源">{{ getSampleSourceText(currentRow.sample_source) }}</el-descriptions-item>
        <el-descriptions-item label="编译时间">{{ formatTimestamp(currentRow.compile_date) }}</el-descriptions-item>
        <el-descriptions-item label="最后分析时间">{{ formatTimestamp(currentRow.last_analy_date) }}</el-descriptions-item>
        
        <el-descriptions-item label="样本描述" :span="2">{{ currentRow.sample_description }}</el-descriptions-item>
        <el-descriptions-item label="告警详情" :span="2">
          <el-input type="textarea" :rows="3" v-model="currentRow.sample_alarm_detail" readonly />
        </el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { getMaliciousSamples } from '../api'
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
    const response = await getMaliciousSamples(currentPage.value, pageSize.value)
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
  const types = { 1: 'info', 2: 'success', 3: 'warning', 4: 'danger', 5: 'danger' }
  return types[severity] || 'info'
}

const getSeverityText = (severity) => {
  const texts = { 1: '信息', 2: '低危', 3: '中危', 4: '高危', 5: '严重' }
  return texts[severity] || '未知'
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

