<template>
  <div class="page-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>🟡 主机行为告警</h2>
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
        <el-table-column prop="host_name" label="主机名" width="180" show-overflow-tooltip />
        <el-table-column prop="terminal_ip" label="终端IP" width="150" />
        <el-table-column prop="user_account" label="用户账号" width="150" show-overflow-tooltip />
        <el-table-column prop="terminal_os" label="操作系统" width="150" />
        <el-table-column prop="src_process_path" label="源进程路径" width="250" show-overflow-tooltip />
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
        <el-descriptions-item label="告警ID">{{ currentRow.alarm_id }}</el-descriptions-item>
        <el-descriptions-item label="告警时间">{{ formatTimestamp(currentRow.alarm_date) }}</el-descriptions-item>
        <el-descriptions-item label="告警名称">{{ currentRow.alarm_name }}</el-descriptions-item>
        <el-descriptions-item label="严重等级">
          <el-tag :type="getSeverityType(currentRow.alarm_severity)">
            {{ getSeverityText(currentRow.alarm_severity) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="告警描述" :span="2">{{ currentRow.alarm_description }}</el-descriptions-item>
        
        <el-descriptions-item label="主机名">{{ currentRow.host_name }}</el-descriptions-item>
        <el-descriptions-item label="终端IP">{{ currentRow.terminal_ip }}</el-descriptions-item>
        <el-descriptions-item label="用户账号">{{ currentRow.user_account }}</el-descriptions-item>
        <el-descriptions-item label="操作系统">{{ currentRow.terminal_os }}</el-descriptions-item>
        <el-descriptions-item label="终端ID">{{ currentRow.terminal_id }}</el-descriptions-item>
        <el-descriptions-item label="协议">{{ currentRow.protocol }}</el-descriptions-item>
        
        <el-descriptions-item label="源IP:端口" :span="2">
          {{ currentRow.src_ip }}{{ currentRow.src_port ? ':' + currentRow.src_port : '' }}
        </el-descriptions-item>
        <el-descriptions-item label="目标IP:端口" :span="2">
          {{ currentRow.dst_ip }}{{ currentRow.dst_port ? ':' + currentRow.dst_port : '' }}
        </el-descriptions-item>
        
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
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { getHostBehaviors } from '../api'
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
    const response = await getHostBehaviors(currentPage.value, pageSize.value)
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

