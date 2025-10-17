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

    <el-table :data="tags" stripe style="width: 100%; margin-top: 20px;" v-loading="loading">
      <el-table-column prop="name" label="标签名称" width="200">
        <template #default="scope">
          <el-tag :color="scope.row.color" style="color: #fff;">
            {{ scope.row.name }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="description" label="描述" />
      <el-table-column prop="usage_count" label="使用次数" width="120" />
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
import { ref, onMounted, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import axios from 'axios'

const tags = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const searchText = ref('')
const dialogVisible = ref(false)
const dialogTitle = ref('添加标签')
const loading = ref(false)
const formData = ref({
  name: '',
  color: '#409EFF',
  description: ''
})

const loadTags = async () => {
  loading.value = true
  try {
    const response = await axios.get('/api/tags', {
      params: {
        page: currentPage.value,
        page_size: pageSize.value,
        search: searchText.value || undefined
      }
    })
    
    tags.value = response.data.data
    total.value = response.data.total
  } catch (error) {
    console.error('加载标签失败:', error)
    ElMessage.error('加载标签失败: ' + (error.response?.data?.message || error.message))
  } finally {
    loading.value = false
  }
}

// 监听分页变化
watch([currentPage, pageSize], () => {
  loadTags()
})

const handleAdd = () => {
  dialogTitle.value = '添加标签'
  formData.value = {
    id: undefined,
    name: '',
    color: '#409EFF',
    description: ''
  }
  dialogVisible.value = true
}

const handleEdit = (row) => {
  dialogTitle.value = '编辑标签'
  formData.value = { 
    id: row.id,
    name: row.name,
    color: row.color,
    description: row.description || ''
  }
  dialogVisible.value = true
}

const handleDelete = async (row) => {
  const confirmMessage = row.usage_count > 0
    ? `该标签已被使用 ${row.usage_count} 次，删除后相关事件的标签也会被移除，确定删除吗？`
    : '确定删除该标签吗?'

  try {
    await ElMessageBox.confirm(confirmMessage, row.usage_count > 0 ? '警告' : '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })

    // 调用 API 删除标签
    await axios.delete(`/api/tags/${row.id}`)
    ElMessage.success('删除成功')
    loadTags()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('删除标签失败:', error)
      ElMessage.error('删除标签失败: ' + (error.response?.data?.message || error.message))
    }
  }
}

const handleSave = async () => {
  if (!formData.value.name.trim()) {
    ElMessage.warning('请输入标签名称')
    return
  }

  try {
    if (formData.value.id) {
      // 更新标签
      await axios.put(`/api/tags/${formData.value.id}`, {
        name: formData.value.name,
        category: 'default',
        color: formData.value.color,
        description: formData.value.description || null
      })
      ElMessage.success('更新成功')
    } else {
      // 创建标签
      await axios.post('/api/tags', {
        name: formData.value.name,
        category: 'default',
        color: formData.value.color,
        description: formData.value.description || null
      })
      ElMessage.success('创建成功')
    }
    
    dialogVisible.value = false
    loadTags()
  } catch (error) {
    console.error('保存标签失败:', error)
    ElMessage.error('保存失败: ' + (error.response?.data?.message || error.message))
  }
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

