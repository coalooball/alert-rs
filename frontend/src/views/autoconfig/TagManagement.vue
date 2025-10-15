<template>
  <div class="tag-management-container">
    <div class="toolbar">
      <el-button type="primary" @click="handleAdd">添加标签</el-button>
      <el-button @click="loadTags">刷新</el-button>
      <el-input 
        v-model="searchText" 
        placeholder="搜索标签名称" 
        style="width: 300px; margin-left: auto;"
        clearable
        @change="loadTags"
      >
        <template #prefix>
          <el-icon><Search /></el-icon>
        </template>
      </el-input>
    </div>

    <el-table :data="tags" stripe style="width: 100%; margin-top: 20px;">
      <el-table-column prop="id" label="标签ID" width="80" />
      <el-table-column prop="name" label="标签名称" width="180">
        <template #default="scope">
          <el-tag :color="scope.row.color" style="color: #fff;">
            {{ scope.row.name }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="category" label="分类" width="120" />
      <el-table-column prop="description" label="描述" />
      <el-table-column prop="usage_count" label="使用次数" width="100" />
      <el-table-column prop="created_at" label="创建时间" width="180" />
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
        <el-form-item label="标签名称">
          <el-input v-model="formData.name" placeholder="请输入标签名称" />
        </el-form-item>
        <el-form-item label="标签分类">
          <el-select v-model="formData.category" placeholder="请选择分类" filterable allow-create>
            <el-option label="优先级" value="优先级" />
            <el-option label="处理方式" value="处理方式" />
            <el-option label="攻击类型" value="攻击类型" />
            <el-option label="业务分类" value="业务分类" />
            <el-option label="其他" value="其他" />
          </el-select>
        </el-form-item>
        <el-form-item label="标签颜色">
          <el-color-picker v-model="formData.color" show-alpha />
          <span style="margin-left: 10px;">{{ formData.color }}</span>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="formData.description" type="textarea" :rows="3" placeholder="请输入标签描述" />
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
import { Search } from '@element-plus/icons-vue'

const tags = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const searchText = ref('')
const dialogVisible = ref(false)
const dialogTitle = ref('添加标签')
const formData = ref({
  name: '',
  category: '',
  color: '#409EFF',
  description: ''
})

const loadTags = () => {
  // TODO: 调用 API 加载标签
  // 示例数据
  tags.value = [
    { 
      id: 1, 
      name: '高优先级', 
      category: '优先级',
      color: '#F56C6C',
      description: '需要优先处理的事件',
      usage_count: 156,
      created_at: '2025-01-10 10:30:00'
    },
    { 
      id: 2, 
      name: '需人工审核', 
      category: '处理方式',
      color: '#E6A23C',
      description: '需要人工介入审核',
      usage_count: 89,
      created_at: '2025-01-11 14:20:00'
    },
    { 
      id: 3, 
      name: '自动处理', 
      category: '处理方式',
      color: '#67C23A',
      description: '可以自动化处理',
      usage_count: 234,
      created_at: '2025-01-12 09:15:00'
    },
    { 
      id: 4, 
      name: 'APT攻击', 
      category: '攻击类型',
      color: '#909399',
      description: '高级持续性威胁',
      usage_count: 12,
      created_at: '2025-01-13 16:45:00'
    },
    { 
      id: 5, 
      name: '误报', 
      category: '其他',
      color: '#909399',
      description: '误报事件',
      usage_count: 67,
      created_at: '2025-01-14 11:00:00'
    }
  ]
  
  // 根据搜索文本过滤
  if (searchText.value) {
    tags.value = tags.value.filter(tag => 
      tag.name.includes(searchText.value) || 
      tag.description.includes(searchText.value)
    )
  }
  
  total.value = tags.value.length
}

const handleAdd = () => {
  dialogTitle.value = '添加标签'
  formData.value = {
    name: '',
    category: '',
    color: '#409EFF',
    description: ''
  }
  dialogVisible.value = true
}

const handleEdit = (row) => {
  dialogTitle.value = '编辑标签'
  formData.value = { ...row }
  dialogVisible.value = true
}

const handleDelete = (row) => {
  if (row.usage_count > 0) {
    ElMessageBox.confirm(
      `该标签已被使用 ${row.usage_count} 次，删除后相关事件的标签也会被移除，确定删除吗？`, 
      '警告', 
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    ).then(() => {
      // TODO: 调用 API 删除标签
      ElMessage.success('删除成功')
      loadTags()
    })
  } else {
    ElMessageBox.confirm('确定删除该标签吗?', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    }).then(() => {
      // TODO: 调用 API 删除标签
      ElMessage.success('删除成功')
      loadTags()
    })
  }
}

const handleSave = () => {
  if (!formData.value.name) {
    ElMessage.warning('请输入标签名称')
    return
  }
  if (!formData.value.category) {
    ElMessage.warning('请选择标签分类')
    return
  }
  // TODO: 调用 API 保存标签
  ElMessage.success('保存成功')
  dialogVisible.value = false
  loadTags()
}

onMounted(() => {
  loadTags()
})
</script>

<style scoped>
.tag-management-container {
  padding: 20px;
}

.toolbar {
  display: flex;
  gap: 10px;
  align-items: center;
}
</style>

