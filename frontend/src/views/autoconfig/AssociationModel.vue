<template>
  <div class="association-model-container">
    <div class="toolbar">
      <el-button type="primary" @click="handleAdd">添加模型</el-button>
      <el-button @click="loadModels">刷新</el-button>
    </div>

    <el-table :data="models" stripe style="width: 100%; margin-top: 20px;">
      <el-table-column prop="id" label="模型ID" width="80" />
      <el-table-column prop="name" label="模型名称" width="200" />
      <el-table-column prop="description" label="描述" :show-overflow-tooltip="true" />
      <el-table-column prop="time_window" label="时间窗口" width="120">
        <template #default="scope">
          <el-tag>{{ scope.row.time_window }} 分钟</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="alert_types" label="关联告警类型" width="180">
        <template #default="scope">
          <el-tag v-for="(type, index) in scope.row.alert_types" :key="index" size="small" style="margin-right: 5px;">
            {{ getAlertTypeName(type) }}
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
        <el-form-item label="模型名称">
          <el-input v-model="formData.name" placeholder="请输入模型名称" />
        </el-form-item>
        
        <el-form-item label="时间窗口">
          <el-input-number 
            v-model="formData.time_window" 
            :min="1" 
            :max="1440"
            placeholder="请输入时间窗口"
            style="width: 100%;"
          />
          <span style="margin-left: 10px; color: #909399; font-size: 12px;">分钟（范围：1-1440）</span>
        </el-form-item>

        <el-form-item label="关联告警类型">
          <el-select 
            v-model="formData.alert_types" 
            multiple 
            placeholder="请选择关联的告警类型"
            style="width: 100%;"
          >
            <el-option label="网络攻击" :value="1" />
            <el-option label="主机行为" :value="2" />
            <el-option label="恶意样本" :value="3" />
          </el-select>
        </el-form-item>

        <el-form-item label="最小告警数量">
          <el-input-number 
            v-model="formData.min_alert_count" 
            :min="2" 
            :max="100"
            placeholder="最小告警数量"
            style="width: 100%;"
          />
          <span style="margin-left: 10px; color: #909399; font-size: 12px;">触发关联的最小告警数</span>
        </el-form-item>

        <el-form-item label="威胁等级">
          <el-select v-model="formData.severity" placeholder="请选择威胁等级" style="width: 100%;">
            <el-option label="低危" :value="1" />
            <el-option label="中危" :value="2" />
            <el-option label="高危" :value="3" />
            <el-option label="严重" :value="4" />
          </el-select>
        </el-form-item>

        <el-form-item label="描述">
          <el-input 
            v-model="formData.description" 
            type="textarea" 
            :rows="4" 
            placeholder="请输入模型描述"
          />
        </el-form-item>

        <el-form-item label="状态">
          <el-switch v-model="formData.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="dialog-footer">
          <el-button @click="dialogVisible = false">取消</el-button>
          <el-button type="primary" @click="handleSave">保存</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'

const models = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const dialogVisible = ref(false)
const dialogTitle = ref('添加模型')
const formData = ref({
  name: '',
  time_window: 10,
  alert_types: [],
  min_alert_count: 3,
  severity: 3,
  description: '',
  enabled: true
})

// 假数据
const mockModels = [
  {
    id: 1,
    name: '横向移动检测模型',
    description: '检测攻击者在内网中的横向移动行为，通过关联登录、访问和攻击事件',
    time_window: 30,
    alert_types: [1, 2],
    correlation_fields: ['src_ip', 'dst_ip', 'user_account'],
    min_alert_count: 3,
    severity: 4,
    enabled: true,
    created_at: '2024-01-15 10:30:00',
    updated_at: '2024-01-15 10:30:00'
  },
  {
    id: 2,
    name: 'APT攻击链检测模型',
    description: '检测APT组织的完整攻击链，包括恶意样本投递、C2通信和数据泄露',
    time_window: 60,
    alert_types: [1, 2, 3],
    correlation_fields: ['terminal_ip', 'dst_ip', 'apt_group'],
    min_alert_count: 4,
    severity: 4,
    enabled: true,
    created_at: '2024-01-14 14:20:00',
    updated_at: '2024-01-14 14:20:00'
  },
  {
    id: 3,
    name: '暴力破解后渗透模型',
    description: '检测暴力破解成功后的后续渗透行为',
    time_window: 15,
    alert_types: [1, 2],
    correlation_fields: ['dst_ip', 'terminal_ip', 'user_account'],
    min_alert_count: 2,
    severity: 3,
    enabled: true,
    created_at: '2024-01-13 09:15:00',
    updated_at: '2024-01-13 09:15:00'
  },
  {
    id: 4,
    name: '恶意样本传播模型',
    description: '检测恶意样本在多台主机间的传播行为',
    time_window: 20,
    alert_types: [3],
    correlation_fields: ['md5', 'sha256', 'terminal_ip'],
    min_alert_count: 5,
    severity: 3,
    enabled: true,
    created_at: '2024-01-12 16:40:00',
    updated_at: '2024-01-12 16:40:00'
  },
  {
    id: 5,
    name: '漏洞利用后门植入模型',
    description: '检测漏洞利用成功后的后门植入行为',
    time_window: 10,
    alert_types: [1, 2, 3],
    correlation_fields: ['dst_ip', 'terminal_ip', 'process_path'],
    min_alert_count: 2,
    severity: 4,
    enabled: false,
    created_at: '2024-01-11 11:25:00',
    updated_at: '2024-01-11 11:25:00'
  },
  {
    id: 6,
    name: '内网扫描后攻击模型',
    description: '检测内网扫描后的针对性攻击行为',
    time_window: 45,
    alert_types: [1],
    correlation_fields: ['src_ip', 'dst_ip'],
    min_alert_count: 10,
    severity: 2,
    enabled: true,
    created_at: '2024-01-10 13:50:00',
    updated_at: '2024-01-10 13:50:00'
  }
]

const getAlertTypeName = (type) => {
  const typeMap = {
    1: '网络攻击',
    2: '主机行为',
    3: '恶意样本'
  }
  return typeMap[type] || '未知'
}

const loadModels = () => {
  // 使用假数据
  const start = (currentPage.value - 1) * pageSize.value
  const end = start + pageSize.value
  models.value = mockModels.slice(start, end)
  total.value = mockModels.length
}

const handleAdd = () => {
  dialogTitle.value = '添加模型'
  formData.value = {
    name: '',
    time_window: 10,
    alert_types: [],
    min_alert_count: 3,
    severity: 3,
    description: '',
    enabled: true
  }
  dialogVisible.value = true
}

const handleEdit = (row) => {
  dialogTitle.value = '编辑模型'
  formData.value = { ...row }
  dialogVisible.value = true
}

const handleDelete = (row) => {
  ElMessageBox.confirm('确定删除该模型吗?', '提示', {
    confirmButtonText: '确定',
    cancelButtonText: '取消',
    type: 'warning'
  }).then(() => {
    ElMessage.success('删除成功（模拟操作）')
    loadModels()
  }).catch(() => {})
}

const handleSave = () => {
  if (!formData.value.name) {
    ElMessage.warning('请输入模型名称')
    return
  }
  if (!formData.value.time_window) {
    ElMessage.warning('请输入时间窗口')
    return
  }
  if (formData.value.alert_types.length === 0) {
    ElMessage.warning('请选择至少一个关联告警类型')
    return
  }
  
  ElMessage.success('保存成功（模拟操作）')
  dialogVisible.value = false
  loadModels()
}

onMounted(() => {
  loadModels()
})
</script>

<style scoped>
.association-model-container {
  padding: 20px;
}

.toolbar {
  display: flex;
  gap: 10px;
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}
</style>

