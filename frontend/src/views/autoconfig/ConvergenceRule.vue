<template>
  <div class="convergence-rule-container">
    <div class="toolbar">
      <el-button type="primary" @click="handleAdd">添加规则</el-button>
      <el-button @click="loadRules">刷新</el-button>
      <el-button @click="showDslHelp = true" type="info">DSL语法帮助</el-button>
    </div>

    <el-table :data="rules" stripe style="width: 100%; margin-top: 20px;">
      <el-table-column prop="id" label="规则ID" width="80" />
      <el-table-column prop="name" label="规则名称" width="200" />
      <el-table-column prop="dsl_rule" label="DSL规则" :show-overflow-tooltip="true">
        <template #default="scope">
          <code class="dsl-preview">{{ scope.row.dsl_rule }}</code>
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
    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="800px">
      <el-form :model="formData" label-width="100px">
        <el-form-item label="规则名称">
          <el-input v-model="formData.name" placeholder="请输入规则名称" />
        </el-form-item>
        <el-form-item label="DSL规则">
          <el-input 
            v-model="formData.dsl_rule" 
            type="textarea" 
            :rows="12" 
            placeholder="请输入收敛规则的DSL表达式"
            class="dsl-editor"
          />
          <div class="dsl-hint">
            <el-link type="primary" @click="insertExample">插入示例</el-link>
            <span class="hint-text">收敛规则用于在时间窗口内对满足条件的告警进行分组合并</span>
          </div>
          <!-- 编译测试结果 -->
          <el-alert
            v-if="compileResult"
            :type="compileResult.type"
            :title="compileResult.title"
            :description="compileResult.message"
            :closable="true"
            @close="compileResult = null"
            style="margin-top: 10px;"
          />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="formData.description" type="textarea" :rows="3" placeholder="请输入规则描述" />
        </el-form-item>
        <el-form-item label="状态">
          <el-switch v-model="formData.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="dialog-footer">
          <div class="footer-left">
            <el-button @click="handleCompileTest" :loading="compiling">
              <el-icon style="margin-right: 4px;"><Document /></el-icon>
              编译测试
            </el-button>
          </div>
          <div class="footer-right">
            <el-button @click="dialogVisible = false">取消</el-button>
            <el-button type="primary" @click="handleSave">保存</el-button>
          </div>
        </div>
      </template>
    </el-dialog>

    <!-- DSL 语法帮助对话框 -->
    <el-dialog v-model="showDslHelp" title="收敛规则 DSL 语法帮助" width="900px">
      <div class="dsl-help">
        <h3>DSL 规则语法</h3>
        <p>收敛规则用于在指定时间窗口内，对满足条件的告警按照指定字段分组，当组内告警数量超过阈值时触发收敛。</p>
        
        <h4>规则结构</h4>
        <pre><code>CONVERGE
  WHERE &lt;条件表达式&gt;
  GROUP BY &lt;字段列表&gt;
  WINDOW &lt;时间窗口&gt;
  THRESHOLD &lt;阈值&gt;</code></pre>

        <h4>可用字段（根据告警类型）</h4>
        <ul>
          <li><strong>通用字段：</strong>alarm_id, alarm_date, alarm_severity, alarm_name, alarm_type, alarm_subtype, source</li>
          <li><strong>网络字段：</strong>src_ip, src_port, dst_ip, dst_port, protocol, session_id</li>
          <li><strong>主机字段：</strong>host_name, terminal_ip, user_account, terminal_os, process_path</li>
          <li><strong>样本字段：</strong>md5, sha256, sample_family, apt_group, file_type</li>
        </ul>

        <h4>条件操作符</h4>
        <ul>
          <li><code>==</code> 等于</li>
          <li><code>!=</code> 不等于</li>
          <li><code>&gt;</code>, <code>&lt;</code>, <code>&gt;=</code>, <code>&lt;=</code> 大于、小于、大于等于、小于等于</li>
          <li><code>CONTAINS</code> 包含</li>
          <li><code>REGEX</code> 正则匹配</li>
          <li><code>IN</code> 在列表中</li>
          <li><code>AND</code>, <code>OR</code>, <code>NOT</code> 逻辑运算符</li>
        </ul>

        <h4>时间窗口单位</h4>
        <ul>
          <li><code>m</code> 或 <code>minutes</code> - 分钟</li>
          <li><code>h</code> 或 <code>hours</code> - 小时</li>
          <li><code>d</code> 或 <code>days</code> - 天</li>
        </ul>

        <h4>示例 1：相同源IP的高危告警收敛</h4>
        <pre><code>CONVERGE
  WHERE alarm_severity >= 3
  GROUP BY src_ip, alarm_type
  WINDOW 5m
  THRESHOLD 10</code></pre>

        <h4>示例 2：同一主机的进程行为告警收敛</h4>
        <pre><code>CONVERGE
  WHERE alarm_type == 2 AND host_name REGEX "^server-.*"
  GROUP BY host_name, user_account
  WINDOW 10m
  THRESHOLD 20</code></pre>

        <h4>示例 3：APT组织相关告警收敛</h4>
        <pre><code>CONVERGE
  WHERE apt_group != "" AND alarm_severity >= 2
  GROUP BY apt_group, dst_ip
  WINDOW 30m
  THRESHOLD 5</code></pre>

        <h4>示例 4：特定端口扫描收敛</h4>
        <pre><code>CONVERGE
  WHERE alarm_subtype IN (1001, 1002, 1003)
    AND dst_port IN (22, 3389, 445, 135)
  GROUP BY src_ip, dst_port
  WINDOW 15m
  THRESHOLD 50</code></pre>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Document } from '@element-plus/icons-vue'

const rules = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const dialogVisible = ref(false)
const dialogTitle = ref('添加规则')
const showDslHelp = ref(false)
const compiling = ref(false)
const compileResult = ref(null)
const formData = ref({
  name: '',
  dsl_rule: '',
  description: '',
  enabled: true
})

const dslExample = `CONVERGE
  WHERE alarm_severity >= 3
  GROUP BY src_ip, alarm_type
  WINDOW 5m
  THRESHOLD 10`

const loadRules = () => {
  // TODO: 调用 API 加载收敛规则
  // 示例数据
  rules.value = [
    { 
      id: 1, 
      name: '相同源IP高危告警收敛', 
      dsl_rule: 'CONVERGE WHERE alarm_severity >= 3 GROUP BY src_ip, alarm_type WINDOW 5m THRESHOLD 10',
      enabled: true 
    },
    { 
      id: 2, 
      name: '主机行为告警收敛', 
      dsl_rule: 'CONVERGE WHERE alarm_type == 2 GROUP BY host_name, user_account WINDOW 10m THRESHOLD 20',
      enabled: true 
    }
  ]
  total.value = rules.value.length
}

const handleAdd = () => {
  dialogTitle.value = '添加规则'
  formData.value = {
    name: '',
    dsl_rule: '',
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
  if (!formData.value.name) {
    ElMessage.warning('请输入规则名称')
    return
  }
  if (!formData.value.dsl_rule) {
    ElMessage.warning('请输入DSL规则')
    return
  }
  // TODO: 调用 API 保存规则
  ElMessage.success('保存成功')
  dialogVisible.value = false
  loadRules()
}

const insertExample = () => {
  formData.value.dsl_rule = dslExample
  compileResult.value = null
}

const handleCompileTest = async () => {
  if (!formData.value.dsl_rule) {
    ElMessage.warning('请输入DSL规则')
    return
  }
  
  compiling.value = true
  compileResult.value = null
  
  try {
    const response = await fetch('/api/rules/convergence/compile', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        dsl_rule: formData.value.dsl_rule
      })
    })
    
    // 检查 HTTP 状态码
    if (!response.ok) {
      throw new Error(`HTTP错误: ${response.status}`)
    }
    
    const result = await response.json()
    
    if (result.success) {
      compileResult.value = {
        type: 'success',
        title: '编译成功',
        message: result.message || 'DSL 规则语法正确，可以正常使用。已验证规则结构、字段名称和操作符。'
      }
      ElMessage.success('DSL 规则编译测试通过')
    } else {
      compileResult.value = {
        type: 'error',
        title: '编译失败',
        message: result.error || '编译失败，请检查DSL语法。'
      }
    }
  } catch (error) {
    console.error('编译测试错误:', error)
    compileResult.value = {
      type: 'error',
      title: '编译失败',
      message: error.message || '无法连接到编译服务，请稍后重试。'
    }
  } finally {
    compiling.value = false
  }
}

onMounted(() => {
  loadRules()
})
</script>

<style scoped>
.convergence-rule-container {
  padding: 20px;
}

.toolbar {
  display: flex;
  gap: 10px;
}

.dsl-preview {
  font-family: 'Courier New', monospace;
  font-size: 13px;
  color: #409eff;
  background-color: #f5f7fa;
  padding: 2px 6px;
  border-radius: 3px;
}

.dsl-editor :deep(textarea) {
  font-family: 'Courier New', monospace;
  font-size: 14px;
  line-height: 1.6;
}

.dsl-hint {
  margin-top: 8px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.hint-text {
  font-size: 12px;
  color: #909399;
}

.dsl-help h3 {
  margin-top: 0;
  color: #303133;
}

.dsl-help h4 {
  margin-top: 20px;
  margin-bottom: 10px;
  color: #606266;
}

.dsl-help pre {
  background-color: #f5f7fa;
  padding: 12px;
  border-radius: 4px;
  overflow-x: auto;
}

.dsl-help code {
  font-family: 'Courier New', monospace;
  font-size: 13px;
  color: #303133;
}

.dsl-help ul {
  margin: 10px 0;
  padding-left: 25px;
}

.dsl-help li {
  margin: 5px 0;
  line-height: 1.6;
}

.dsl-help p {
  line-height: 1.6;
  color: #606266;
}

.dialog-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

.footer-left {
  display: flex;
  gap: 10px;
}

.footer-right {
  display: flex;
  gap: 10px;
}
</style>

