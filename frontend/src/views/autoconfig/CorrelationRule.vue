<template>
  <div class="correlation-rule-container">
    <div class="toolbar">
      <el-button type="primary" @click="handleAdd">添加规则</el-button>
      <el-button @click="loadRules">刷新</el-button>
    </div>

    <el-table :data="rules" stripe style="width: 100%; margin-top: 20px;">
      <el-table-column prop="id" label="规则ID" width="80" />
      <el-table-column prop="name" label="规则名称" width="180" />
      <el-table-column prop="event_types" label="关联事件类型" />
      <el-table-column prop="time_window" label="时间窗口" width="120">
        <template #default="scope">
          {{ scope.row.time_window }}分钟
        </template>
      </el-table-column>
      <el-table-column prop="severity" label="生成等级" width="100">
        <template #default="scope">
          <el-tag :type="getSeverityType(scope.row.severity)">
            {{ getSeverityText(scope.row.severity) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="enabled" label="状态" width="80">
        <template #default="scope">
          <el-tag :type="scope.row.enabled ? 'success' : 'info'">
            {{ scope.row.enabled ? '启用' : '禁用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="180" fixed="right">
        <template #default="scope">
          <el-button link type="primary" size="small" @click="handleEdit(scope.row)">编辑</el-button>
          <el-button link type="danger" size="small" @click="handleDelete(scope.row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-pagination
      v-model:current-page="currentPage"
      v-model:page-size="pageSize"
      :total="total"
      :page-sizes="[10, 20, 50, 100]"
      layout="total, sizes, prev, pager, next, jumper"
      style="margin-top: 20px; justify-content: center;"
    />

    <!-- 添加/编辑对话框 -->
    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="700px">
      <el-form :model="formData" label-width="120px">
        <el-form-item label="规则名称">
          <el-input v-model="formData.name" placeholder="请输入规则名称" />
        </el-form-item>
        <el-form-item label="关联事件类型">
          <el-select v-model="formData.event_types" multiple placeholder="请选择事件类型">
            <el-option label="网络攻击" value="network_attack" />
            <el-option label="恶意样本" value="malicious_sample" />
            <el-option label="主机行为" value="host_behavior" />
            <el-option label="威胁事件" value="threat_event" />
          </el-select>
        </el-form-item>
        <el-form-item label="关联字段">
          <el-select v-model="formData.correlation_fields" multiple placeholder="请选择关联字段">
            <el-option label="源IP" value="source_ip" />
            <el-option label="目标IP" value="target_ip" />
            <el-option label="资产名称" value="asset_name" />
            <el-option label="用户" value="user" />
            <el-option label="进程名" value="process_name" />
          </el-select>
        </el-form-item>
        <el-form-item label="时间窗口">
          <el-input-number v-model="formData.time_window" :min="1" :max="1440" /> 分钟
        </el-form-item>
        <el-form-item label="生成威胁等级">
          <el-select v-model="formData.severity" placeholder="请选择等级">
            <el-option label="低危" value="low" />
            <el-option label="中危" value="medium" />
            <el-option label="高危" value="high" />
            <el-option label="严重" value="critical" />
          </el-select>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="formData.description" type="textarea" :rows="3" placeholder="请输入规则描述" />
        </el-form-item>
        <el-form-item label="状态">
          <el-switch v-model="formData.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleSave">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'

const rules = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const dialogVisible = ref(false)
const dialogTitle = ref('添加规则')
const formData = ref({
  name: '',
  event_types: [],
  correlation_fields: [],
  time_window: 10,
  severity: 'medium',
  description: '',
  enabled: true
})

const getSeverityType = (severity) => {
  const types = {
    low: 'info',
    medium: 'warning',
    high: 'danger',
    critical: 'danger'
  }
  return types[severity] || 'info'
}

const getSeverityText = (severity) => {
  const texts = {
    low: '低危',
    medium: '中危',
    high: '高危',
    critical: '严重'
  }
  return texts[severity] || severity
}

const loadRules = () => {
  // TODO: 调用 API 加载关联规则
  // 示例数据
  rules.value = [
    { 
      id: 1, 
      name: '攻击链关联', 
      event_types: ['network_attack', 'host_behavior'], 
      time_window: 10, 
      severity: 'high', 
      enabled: true 
    },
    { 
      id: 2, 
      name: '横向移动检测', 
      event_types: ['network_attack', 'malicious_sample'], 
      time_window: 30, 
      severity: 'critical', 
      enabled: true 
    }
  ]
  total.value = rules.value.length
}

const handleAdd = () => {
  dialogTitle.value = '添加规则'
  formData.value = {
    name: '',
    event_types: [],
    correlation_fields: [],
    time_window: 10,
    severity: 'medium',
    description: '',
    enabled: true
  }
  dialogVisible.value = true
}

const handleEdit = (row) => {
  dialogTitle.value = '编辑规则'
  formData.value = { ...row }
  dialogVisible.value = true
}

const handleDelete = (row) => {
  ElMessageBox.confirm('确定删除该规则吗?', '提示', {
    confirmButtonText: '确定',
    cancelButtonText: '取消',
    type: 'warning'
  }).then(() => {
    // TODO: 调用 API 删除规则
    ElMessage.success('删除成功')
    loadRules()
  })
}

const handleSave = () => {
  // TODO: 调用 API 保存规则
  ElMessage.success('保存成功')
  dialogVisible.value = false
  loadRules()
}

onMounted(() => {
  loadRules()
})
</script>

<style scoped>
.correlation-rule-container {
  padding: 20px;
}

.toolbar {
  display: flex;
  gap: 10px;
}
</style>

