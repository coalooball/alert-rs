<template>
  <div class="filter-rule-container">
    <div class="toolbar">
      <el-button type="primary" @click="handleAdd">添加规则</el-button>
      <el-button @click="loadRules">刷新</el-button>
    </div>

    <el-table :data="rules" stripe style="width: 100%; margin-top: 20px;">
      <el-table-column prop="id" label="规则ID" width="80" />
      <el-table-column prop="name" label="规则名称" width="180" />
      <el-table-column prop="field" label="过滤字段" width="120" />
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
    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="600px">
      <el-form :model="formData" label-width="100px">
        <el-form-item label="规则名称">
          <el-input v-model="formData.name" placeholder="请输入规则名称" />
        </el-form-item>
        <el-form-item label="过滤字段">
          <el-select v-model="formData.field" placeholder="请选择字段">
            <el-option label="事件类型" value="event_type" />
            <el-option label="严重程度" value="severity" />
            <el-option label="源IP" value="source_ip" />
            <el-option label="目标IP" value="target_ip" />
            <el-option label="资产名称" value="asset_name" />
          </el-select>
        </el-form-item>
        <el-form-item label="操作符">
          <el-select v-model="formData.operator" placeholder="请选择操作符">
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
  field: '',
  operator: '',
  value: '',
  enabled: true
})

const loadRules = () => {
  // TODO: 调用 API 加载过滤规则
  // 示例数据
  rules.value = [
    { id: 1, name: '过滤低危事件', field: 'severity', operator: 'eq', value: 'low', enabled: true },
    { id: 2, name: '过滤测试IP', field: 'source_ip', operator: 'contains', value: '192.168.1', enabled: true }
  ]
  total.value = rules.value.length
}

const handleAdd = () => {
  dialogTitle.value = '添加规则'
  formData.value = {
    name: '',
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
.filter-rule-container {
  padding: 20px;
}

.toolbar {
  display: flex;
  gap: 10px;
}
</style>

