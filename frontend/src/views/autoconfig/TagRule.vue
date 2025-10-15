<template>
  <div class="tag-rule-container">
    <div class="toolbar">
      <el-button type="primary" @click="handleAdd">添加规则</el-button>
      <el-button @click="loadRules">刷新</el-button>
    </div>

    <el-table :data="rules" stripe style="width: 100%; margin-top: 20px;">
      <el-table-column prop="id" label="规则ID" width="80" />
      <el-table-column prop="name" label="规则名称" width="180" />
      <el-table-column prop="condition_field" label="条件字段" width="120" />
      <el-table-column prop="condition_operator" label="操作符" width="100" />
      <el-table-column prop="condition_value" label="条件值" />
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
    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="600px">
      <el-form :model="formData" label-width="100px">
        <el-form-item label="规则名称">
          <el-input v-model="formData.name" placeholder="请输入规则名称" />
        </el-form-item>
        <el-form-item label="条件字段">
          <el-select v-model="formData.condition_field" placeholder="请选择字段">
            <el-option label="事件类型" value="event_type" />
            <el-option label="严重程度" value="severity" />
            <el-option label="源IP" value="source_ip" />
            <el-option label="目标IP" value="target_ip" />
            <el-option label="资产名称" value="asset_name" />
            <el-option label="攻击类型" value="attack_type" />
            <el-option label="样本类型" value="sample_type" />
          </el-select>
        </el-form-item>
        <el-form-item label="操作符">
          <el-select v-model="formData.condition_operator" placeholder="请选择操作符">
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
          <el-select v-model="formData.tags" multiple filterable allow-create placeholder="请选择或输入标签">
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
  condition_field: '',
  condition_operator: '',
  condition_value: '',
  tags: [],
  description: '',
  enabled: true
})

const loadRules = () => {
  // TODO: 调用 API 加载标签规则
  // 示例数据
  rules.value = [
    { 
      id: 1, 
      name: '高危事件标记', 
      condition_field: 'severity', 
      condition_operator: 'eq', 
      condition_value: 'high', 
      tags: ['高优先级', '需人工审核'],
      enabled: true 
    },
    { 
      id: 2, 
      name: 'APT攻击标记', 
      condition_field: 'attack_type', 
      condition_operator: 'contains', 
      condition_value: 'APT', 
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
.tag-rule-container {
  padding: 20px;
}

.toolbar {
  display: flex;
  gap: 10px;
}
</style>

