<template>
  <div class="filter-rule-container">
    <div class="toolbar">
      <el-button type="primary" @click="handleAdd">添加规则</el-button>
      <el-button @click="loadRules">刷新</el-button>
    </div>

    <el-table :data="rules" stripe style="width: 100%; margin-top: 20px;">
      <el-table-column prop="name" label="规则名称" width="150" />
      <el-table-column prop="alert_type" label="告警类型" width="140">
        <template #default="scope">
          {{ getAlertTypeName(scope.row.alert_type) }}
        </template>
      </el-table-column>
      <el-table-column prop="alert_subtype" label="告警子类型" width="140">
        <template #default="scope">
          {{ getAlertSubtypeName(scope.row.alert_type, scope.row.alert_subtype) }}
        </template>
      </el-table-column>
      <el-table-column prop="field" label="过滤字段" width="140" />
      <el-table-column prop="operator" label="操作符" width="100" />
      <el-table-column prop="value" label="过滤值" />
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
        
        <el-form-item label="过滤字段">
          <el-select 
            v-model="formData.field" 
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
          <el-select v-model="formData.operator" placeholder="请选择操作符" style="width: 100%;">
            <el-option label="等于" value="eq" />
            <el-option label="不等于" value="ne" />
            <el-option label="包含" value="contains" />
            <el-option label="不包含" value="not_contains" />
            <el-option label="正则匹配" value="regex" />
          </el-select>
        </el-form-item>
        
        <el-form-item label="过滤值">
          <el-input v-model="formData.value" placeholder="请输入过滤值" />
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

// 表单数据
const formData = ref({
  name: '',
  alert_type: '',  // 告警类型: network_attack, malicious_sample, host_behavior
  alert_subtype: '',  // 告警子类型
  field: '',  // 过滤字段
  operator: '',
  value: '',
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
  formData.value.field = ''
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

const loadRules = async () => {
  try {
    const response = await fetch(`/api/rules/filter?page=${currentPage.value}&page_size=${pageSize.value}`)
    const result = await response.json()
    
    if (result.success && result.data) {
      rules.value = result.data.items
      total.value = result.data.total
    } else {
      ElMessage.error(result.error || '加载过滤规则失败')
    }
  } catch (error) {
    console.error('加载过滤规则失败:', error)
    ElMessage.error('加载过滤规则失败')
  }
}

const handleAdd = () => {
  dialogTitle.value = '添加规则'
  formData.value = {
    name: '',
    alert_type: '',
    alert_subtype: '',
    field: '',
    operator: '',
    value: '',
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
  }).then(async () => {
    try {
      const response = await fetch(`/api/rules/filter/${row.id}`, {
        method: 'DELETE'
      })
      const result = await response.json()
      
      if (result.success) {
        ElMessage.success('删除成功')
        loadRules()
      } else {
        ElMessage.error(result.error || '删除失败')
      }
    } catch (error) {
      console.error('删除失败:', error)
      ElMessage.error('删除失败')
    }
  }).catch(() => {})
}

const handleSave = async () => {
  if (!formData.value.name) {
    ElMessage.warning('请输入规则名称')
    return
  }
  if (!formData.value.alert_type) {
    ElMessage.warning('请选择告警类型')
    return
  }
  if (!formData.value.alert_subtype) {
    ElMessage.warning('请选择告警子类型')
    return
  }
  if (!formData.value.field) {
    ElMessage.warning('请选择过滤字段')
    return
  }
  if (!formData.value.operator) {
    ElMessage.warning('请选择操作符')
    return
  }
  if (!formData.value.value) {
    ElMessage.warning('请输入过滤值')
    return
  }
  
  try {
    const isEdit = !!formData.value.id
    const url = isEdit ? `/api/rules/filter/${formData.value.id}` : '/api/rules/filter'
    const method = isEdit ? 'PUT' : 'POST'
    
    const response = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: formData.value.name,
        alert_type: formData.value.alert_type,
        alert_subtype: formData.value.alert_subtype,
        field: formData.value.field,
        operator: formData.value.operator,
        value: formData.value.value,
        enabled: formData.value.enabled
      })
    })
    
    const result = await response.json()
    
    if (result.success) {
      ElMessage.success('保存成功')
      dialogVisible.value = false
      loadRules()
    } else {
      ElMessage.error(result.error || '保存失败')
    }
  } catch (error) {
    console.error('保存失败:', error)
    ElMessage.error('保存失败')
  }
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
  if (!alarmTypes.value || !type || subtype === null || subtype === undefined) return subtype
  const typeConfig = alarmTypes.value[type]
  if (!typeConfig || !typeConfig.subtypes) return subtype
  // 确保 subtype 是字符串，因为 config.toml 的 key 都是字符串
  const subtypeKey = String(subtype)
  return typeConfig.subtypes[subtypeKey] || subtype
}

onMounted(async () => {
  await loadAlarmTypes()
  await loadAlertFields()
  loadRules()
})
</script>

<style scoped>
.filter-rule-container {
  padding: 20px;
}

.toolbar {
  display: flex;
  gap: 10px;
}
</style>

