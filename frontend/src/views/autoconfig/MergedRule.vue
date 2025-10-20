<template>
  <div class="merged-rule-container">
    <div class="toolbar">
      <el-button type="primary" @click="handleAdd">添加规则</el-button>
      <el-button @click="loadRules">刷新</el-button>
      <el-button @click="showDslHelp = true" type="info">DSL语法帮助</el-button>
    </div>

    <el-table :data="rules" stripe style="width: 100%; margin-top: 20px;">
      <el-table-column prop="rule_type" label="规则类型" width="100">
        <template #default="scope">
          <el-tag :type="scope.row.rule_type === 'convergence' ? 'primary' : 'success'">
            {{ scope.row.rule_type === 'convergence' ? '收敛' : '关联' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="name" label="规则名称" width="250" />
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
        <el-form-item label="规则类型">
          <el-select v-model="formData.rule_type" placeholder="请选择规则类型" :disabled="isEdit" style="width: 100%;">
            <el-option label="收敛规则" value="convergence" />
            <el-option label="关联规则" value="correlation" />
          </el-select>
        </el-form-item>
        <el-form-item label="规则名称">
          <el-input v-model="formData.name" placeholder="请输入规则名称" />
        </el-form-item>
        <el-form-item label="DSL规则">
          <el-input 
            v-model="formData.dsl_rule" 
            type="textarea" 
            :rows="12" 
            :placeholder="dslPlaceholder"
            class="dsl-editor"
          />
          <div class="dsl-hint">
            <el-link type="primary" @click="insertExample">插入示例</el-link>
            <span class="hint-text">{{ ruleTypeHint }}</span>
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
    <el-dialog v-model="showDslHelp" title="收敛与关联规则 DSL 语法帮助" width="900px">
      <div class="dsl-help">
        <el-tabs v-model="helpTab">
          <el-tab-pane label="收敛规则" name="convergence">
            <h3>收敛规则 DSL 语法</h3>
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

            <h4>示例：相同源IP的高危告警收敛</h4>
            <pre><code>CONVERGE
  WHERE alarm_severity >= 3
  GROUP BY src_ip, alarm_type
  WINDOW 5m
  THRESHOLD 10</code></pre>

            <h4>示例：同一主机的进程行为告警收敛</h4>
            <pre><code>CONVERGE
  WHERE alarm_type == 2 AND host_name REGEX "^server-.*"
  GROUP BY host_name, user_account
  WINDOW 10m
  THRESHOLD 20</code></pre>
          </el-tab-pane>

          <el-tab-pane label="关联规则" name="correlation">
            <h3>关联规则 DSL 语法</h3>
            <p>关联规则用于在指定时间窗口内检测多个告警之间的关联关系，当检测到符合条件的告警序列时生成关联告警。</p>
            
            <h4>规则结构</h4>
            <pre><code>CORRELATE
  EVENT &lt;事件别名1&gt; WHERE &lt;条件1&gt;
  EVENT &lt;事件别名2&gt; WHERE &lt;条件2&gt;
  [EVENT &lt;事件别名3&gt; WHERE &lt;条件3&gt;]
  JOIN ON &lt;关联条件&gt;
  WINDOW &lt;时间窗口&gt;
  GENERATE
    SEVERITY &lt;威胁等级&gt;
    NAME &lt;告警名称&gt;
    DESCRIPTION &lt;告警描述&gt;</code></pre>

            <h4>示例：攻击链关联检测</h4>
            <pre><code>CORRELATE
  EVENT attack WHERE alarm_type == 1 AND alarm_severity >= 2
  EVENT behavior WHERE alarm_type == 2 AND dst_process_path CONTAINS "cmd.exe"
  JOIN ON attack.dst_ip == behavior.terminal_ip
  WINDOW 10m
  GENERATE
    SEVERITY 3
    NAME "检测到攻击链活动"
    DESCRIPTION "网络攻击后发现可疑主机行为"</code></pre>

            <h4>示例：横向移动检测</h4>
            <pre><code>CORRELATE
  EVENT login WHERE alarm_subtype == 2001 AND alarm_name CONTAINS "登录"
  EVENT access WHERE alarm_subtype == 2002 AND alarm_name CONTAINS "访问"
  EVENT lateral WHERE alarm_subtype == 1005
  JOIN ON login.user_account == access.user_account 
       AND access.dst_ip == lateral.src_ip
  WINDOW 30m
  GENERATE
    SEVERITY 4
    NAME "检测到横向移动"
    DESCRIPTION "发现异常登录后的横向移动行为"</code></pre>
          </el-tab-pane>

          <el-tab-pane label="通用说明" name="common">
            <h3>通用说明</h3>
            
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

            <h4>威胁等级（仅关联规则）</h4>
            <ul>
              <li><code>1</code> - 低危</li>
              <li><code>2</code> - 中危</li>
              <li><code>3</code> - 高危</li>
              <li><code>4</code> - 严重</li>
            </ul>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Document } from '@element-plus/icons-vue'

const rules = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const dialogVisible = ref(false)
const dialogTitle = ref('添加规则')
const showDslHelp = ref(false)
const helpTab = ref('convergence')
const compiling = ref(false)
const compileResult = ref(null)
const isEdit = ref(false)
const formData = ref({
  rule_type: 'convergence',
  name: '',
  dsl_rule: '',
  description: '',
  enabled: true
})

const convergenceExample = `CONVERGE
  WHERE alarm_severity >= 3
  GROUP BY src_ip, alarm_type
  WINDOW 5m
  THRESHOLD 10`

const correlationExample = `CORRELATE
  EVENT attack WHERE alarm_type == 1 AND alarm_severity >= 2
  EVENT behavior WHERE alarm_type == 2 AND dst_process_path CONTAINS "cmd.exe"
  JOIN ON attack.dst_ip == behavior.terminal_ip
  WINDOW 10m
  GENERATE
    SEVERITY 3
    NAME "检测到攻击链活动"
    DESCRIPTION "网络攻击后发现可疑主机行为"`

const dslPlaceholder = computed(() => {
  return formData.value.rule_type === 'convergence' 
    ? '请输入收敛规则的DSL表达式' 
    : '请输入关联规则的DSL表达式'
})

const ruleTypeHint = computed(() => {
  return formData.value.rule_type === 'convergence'
    ? '收敛规则用于在时间窗口内对满足条件的告警进行分组合并'
    : '关联规则用于在时间窗口内检测多个告警之间的关联关系'
})

const loadRules = async () => {
  try {
    // 并行加载收敛规则和关联规则
    const [convergenceRes, correlationRes] = await Promise.all([
      fetch(`/api/rules/convergence?page=1&page_size=1000`),
      fetch(`/api/rules/correlation?page=1&page_size=1000`)
    ])
    
    const convergenceData = await convergenceRes.json()
    const correlationData = await correlationRes.json()
    
    let allRules = []
    
    // 添加收敛规则
    if (convergenceData.success && convergenceData.data) {
      const convergenceRules = convergenceData.data.items.map(rule => ({
        ...rule,
        rule_type: 'convergence'
      }))
      allRules = allRules.concat(convergenceRules)
    }
    
    // 添加关联规则
    if (correlationData.success && correlationData.data) {
      const correlationRules = correlationData.data.items.map(rule => ({
        ...rule,
        rule_type: 'correlation'
      }))
      allRules = allRules.concat(correlationRules)
    }
    
    // 分页处理
    total.value = allRules.length
    const start = (currentPage.value - 1) * pageSize.value
    const end = start + pageSize.value
    rules.value = allRules.slice(start, end)
    
  } catch (error) {
    console.error('加载规则失败:', error)
    ElMessage.error('加载规则失败')
  }
}

const handleAdd = () => {
  dialogTitle.value = '添加规则'
  isEdit.value = false
  formData.value = {
    rule_type: 'convergence',
    name: '',
    dsl_rule: '',
    description: '',
    enabled: true
  }
  compileResult.value = null
  dialogVisible.value = true
}

const handleEdit = (row) => {
  dialogTitle.value = '编辑规则'
  isEdit.value = true
  formData.value = { ...row }
  compileResult.value = null
  dialogVisible.value = true
}

const handleDelete = (row) => {
  ElMessageBox.confirm('确定删除该规则吗?', '提示', {
    confirmButtonText: '确定',
    cancelButtonText: '取消',
    type: 'warning'
  }).then(async () => {
    try {
      const apiPath = row.rule_type === 'convergence' ? 'convergence' : 'correlation'
      const response = await fetch(`/api/rules/${apiPath}/${row.id}`, {
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
  if (!formData.value.rule_type) {
    ElMessage.warning('请选择规则类型')
    return
  }
  if (!formData.value.name) {
    ElMessage.warning('请输入规则名称')
    return
  }
  if (!formData.value.dsl_rule) {
    ElMessage.warning('请输入DSL规则')
    return
  }
  
  try {
    const apiPath = formData.value.rule_type === 'convergence' ? 'convergence' : 'correlation'
    const isEditMode = !!formData.value.id
    const url = isEditMode ? `/api/rules/${apiPath}/${formData.value.id}` : `/api/rules/${apiPath}`
    const method = isEditMode ? 'PUT' : 'POST'
    
    const response = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: formData.value.name,
        dsl_rule: formData.value.dsl_rule,
        description: formData.value.description || null,
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

const insertExample = () => {
  formData.value.dsl_rule = formData.value.rule_type === 'convergence' 
    ? convergenceExample 
    : correlationExample
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
    const apiPath = formData.value.rule_type === 'convergence' ? 'convergence' : 'correlation'
    const response = await fetch(`/api/rules/${apiPath}/compile`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        dsl_rule: formData.value.dsl_rule
      })
    })
    
    if (!response.ok) {
      throw new Error(`HTTP错误: ${response.status}`)
    }
    
    const result = await response.json()
    
    if (result.success) {
      compileResult.value = {
        type: 'success',
        title: '编译成功',
        message: result.message || 'DSL 规则语法正确，可以正常使用。'
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
.merged-rule-container {
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
