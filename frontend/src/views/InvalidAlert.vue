<template>
  <div class="page-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>无效告警</h2>
          <el-button type="primary" @click="loadData" :loading="loading">
            <el-icon><Refresh /></el-icon> 刷新
          </el-button>
        </div>
      </template>

      <el-table :data="tableData" v-loading="loading" stripe border style="width: 100%">
        <el-table-column type="index" label="序号" width="60" />
        <el-table-column prop="created_at" label="时间" width="180" />
        <el-table-column prop="error" label="错误" min-width="240" show-overflow-tooltip />
        <el-table-column label="原始数据" min-width="300">
          <template #default="{ row }">
            <el-popover trigger="click" placement="left" :width="600">
              <template #reference>
                <el-button size="small">查看</el-button>
              </template>
              <pre class="raw-json">{{ prettyJson(row.data) }}</pre>
            </el-popover>
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
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { getInvalidAlerts } from '../api'
import { ElMessage } from 'element-plus'

const tableData = ref([])
const loading = ref(false)
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)

const loadData = async () => {
  loading.value = true
  try {
    const response = await getInvalidAlerts(currentPage.value, pageSize.value)
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

const prettyJson = (val) => {
  try {
    return JSON.stringify(val, null, 2)
  } catch (e) {
    return String(val)
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

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.raw-json {
  margin: 0;
  max-height: 400px;
  overflow: auto;
  background: #f7f7f7;
  padding: 12px;
  border-radius: 4px;
}
</style>


