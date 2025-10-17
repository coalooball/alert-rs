<template>
  <div class="tag-rule-container">
    <div class="toolbar">
      <el-button type="primary" @click="handleAdd">添加规则</el-button>
      <el-button @click="loadRules">刷新</el-button>
    </div>

    <el-table :data="rules" stripe style="width: 100%; margin-top: 20px;">
      <el-table-column prop="name" label="规则名称" width="150" />
      <el-table-column prop="alert_type" label="告警类型" width="130">
        <template #default="scope">
          {{ getAlertTypeName(scope.row.alert_type) }}
        </template>
      </el-table-column>
      <el-table-column prop="alert_subtype" label="告警子类型" width="130">
        <template #default="scope">
          {{ getAlertSubtypeName(scope.row.alert_type, scope.row.alert_subtype) }}
        </template>
      </el-table-column>
      <el-table-column prop="condition_field" label="条件字段" width="130" />
      <el-table-column prop="condition_operator" label="操作符" width="90" />
      <el-table-column prop="condition_value" label="条件值" width="120" />
      <el-table-column prop="tags" label="添加标签" width="200">
        <template #default="scope">
          <el-tag v-for="tag in scope.row.tags" :key="tag" size="small" style="margin-right: 5px;">
            {{ tag }}
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
        
        <el-form-item label="告警类型">
          <el-select v-model="formData.alert_type" placeholder="请选择告警类型" style="width: 100%;">
            <el-option 
              v-if="alarmTypes?.network_attack"
              label="网络攻击告警" 
              value="network_attack" 
            />
            <el-option 
              v-if="alarmTypes?.malicious_sample"
              label="恶意样本告警" 
              value="malicious_sample" 
            />
            <el-option 
              v-if="alarmTypes?.host_behavior"
              label="主机行为告警" 
              value="host_behavior" 
            />
          </el-select>
        </el-form-item>
        
        <el-form-item label="告警子类型">
          <el-select 
            v-model="formData.alert_subtype" 
            placeholder="请先选择告警类型" 
            :disabled="!formData.alert_type"
            style="width: 100%;"
            filterable
          >
            <el-option
              v-for="subtype in availableSubtypes"
              :key="subtype.value"
              :label="subtype.label"
              :value="subtype.value"
            />
          </el-select>
        </el-form-item>
        
        <el-form-item label="条件字段">
          <el-select 
            v-model="formData.condition_field" 
            placeholder="请先选择告警类型"
            :disabled="!formData.alert_type"
            style="width: 100%;"
            filterable
          >
            <el-option
              v-for="field in availableFields"
              :key="field.value"
              :label="field.label"
              :value="field.value"
            />
          </el-select>
        </el-form-item>
        
        <el-form-item label="操作符">
          <el-select v-model="formData.condition_operator" placeholder="请选择操作符" style="width: 100%;">
            <el-option label="等于" value="eq" />
            <el-option label="不等于" value="ne" />
            <el-option label="包含" value="contains" />
            <el-option label="不包含" value="not_contains" />
            <el-option label="正则匹配" value="regex" />
          </el-select>
        </el-form-item>
        
        <el-form-item label="条件值">
          <el-input v-model="formData.condition_value" placeholder="请输入条件值" />
        </el-form-item>
        
        <el-form-item label="添加标签">
          <el-select v-model="formData.tags" multiple filterable allow-create placeholder="请选择或输入标签" style="width: 100%;">
            <el-option label="高优先级" value="高优先级" />
            <el-option label="需人工审核" value="需人工审核" />
            <el-option label="自动处理" value="自动处理" />
            <el-option label="误报" value="误报" />
            <el-option label="APT攻击" value="APT攻击" />
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
import { ref, onMounted, watch, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import axios from 'axios'

const rules = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const dialogVisible = ref(false)
const dialogTitle = ref('添加规则')

// 告警类型配置
const alarmTypes = ref(null)
const alertFields = ref([])

const formData = ref({
  name: '',
  alert_type: '',
  alert_subtype: '',
  condition_field: '',
  condition_operator: '',
  condition_value: '',
  tags: [],
  description: '',
  enabled: true
})

// 计算可用的告警子类型
const availableSubtypes = computed(() => {
  if (!formData.value.alert_type || !alarmTypes.value) {
    return []
  }
  
  const typeConfig = alarmTypes.value[formData.value.alert_type]
  if (!typeConfig || !typeConfig.subtypes) {
    return []
  }
  
  return Object.entries(typeConfig.subtypes).map(([code, name]) => ({
    value: code,
    label: name
  }))
})

// 计算可用的字段（根据告警类型）
const availableFields = computed(() => {
  if (!formData.value.alert_type || alertFields.value.length === 0) {
    return []
  }
  
  // 映射告警类型到字段类型
  const typeMapping = {
    'network_attack': 'network_attack_alert',
    'malicious_sample': 'malicious_sample_alert',
    'host_behavior': 'host_behavior_alert'
  }
  
  const fieldType = typeMapping[formData.value.alert_type]
  const typeFields = alertFields.value.find(f => f.alert_type === fieldType)
  
  if (!typeFields) {
    return []
  }
  
  return typeFields.fields.map(field => ({
    value: field.name,
    label: `${field.description} (${field.name})`
  }))
})

// 监听告警类型变化，清空依赖字段
watch(() => formData.value.alert_type, () => {
  formData.value.alert_subtype = ''
  formData.value.condition_field = ''
})

// 加载告警类型配置
const loadAlarmTypes = async () => {
  try {
    const response = await axios.get('/api/alarm-types')
    alarmTypes.value = response.data
  } catch (error) {
    console.error('加载告警类型失败:', error)
    ElMessage.error('加载告警类型失败')
  }
}

// 加载字段定义
const loadAlertFields = async () => {
  try {
    const response = await axios.get('/api/alert-fields')
    if (response.data.success) {
      alertFields.value = response.data.data
    }
  } catch (error) {
    console.error('加载字段定义失败:', error)
    ElMessage.error('加载字段定义失败')
  }
}

const loadRules = () => {
  // TODO: 调用 API 加载标签规则
  // 示例数据
  rules.value = [
    { 
      id: 1, 
      name: '高危事件标记',
      alert_type: 'network_attack',
      alert_subtype: '01009',
      condition_field: 'alarm_severity', 
      condition_operator: 'eq', 
      condition_value: '3', 
      tags: ['高优先级', '需人工审核'],
      enabled: true 
    },
    { 
      id: 2, 
      name: 'APT攻击标记',
      alert_type: 'network_attack',
      alert_subtype: '01009',
      condition_field: 'apt_group', 
      condition_operator: 'ne', 
      condition_value: '', 
      tags: ['APT攻击', '高优先级'],
      enabled: true 
    }
  ]
  total.value = rules.value.length
}

const handleAdd = () => {
  dialogTitle.value = '添加规则'
  formData.value = {
    name: '',
    alert_type: '',
    alert_subtype: '',
    condition_field: '',
    condition_operator: '',
    condition_value: '',
    tags: [],
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

// 获取告警类型名称
const getAlertTypeName = (type) => {
  if (!alarmTypes.value || !type) return type
  const typeMap = {
    'network_attack': alarmTypes.value.network_attack?.name,
    'malicious_sample': alarmTypes.value.malicious_sample?.name,
    'host_behavior': alarmTypes.value.host_behavior?.name
  }
  return typeMap[type] || type
}

// 获取告警子类型名称
const getAlertSubtypeName = (type, subtype) => {
  if (!alarmTypes.value || !type || !subtype) return subtype
  const typeConfig = alarmTypes.value[type]
  if (!typeConfig || !typeConfig.subtypes) return subtype
  return typeConfig.subtypes[subtype] || subtype
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
  loadAlarmTypes()
  loadAlertFields()
  loadRules()
})
</script>

<style scoped>
.tag-rule-container {
  padding: 20px;
}

.toolbar {
  display: flex;
  gap: 10px;
}
</style>

