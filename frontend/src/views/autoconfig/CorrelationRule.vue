<template>
  <div class="correlation-rule-container">
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
            :rows="14" 
            placeholder="请输入关联规则的DSL表达式"
            class="dsl-editor"
          />
          <div class="dsl-hint">
            <el-link type="primary" @click="insertExample">插入示例</el-link>
            <span class="hint-text">关联规则用于在时间窗口内检测多个告警之间的关联关系</span>
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
    <el-dialog v-model="showDslHelp" title="关联规则 DSL 语法帮助" width="900px">
      <div class="dsl-help">
        <h3>DSL 规则语法</h3>
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

        <h4>可用字段（根据告警类型）</h4>
        <ul>
          <li><strong>通用字段：</strong>alarm_id, alarm_date, alarm_severity, alarm_name, alarm_type, alarm_subtype, source</li>
          <li><strong>网络字段：</strong>src_ip, src_port, dst_ip, dst_port, protocol, session_id</li>
          <li><strong>主机字段：</strong>host_name, terminal_ip, user_account, terminal_os, process_path, file_path</li>
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

        <h4>威胁等级</h4>
        <ul>
          <li><code>1</code> - 低危</li>
          <li><code>2</code> - 中危</li>
          <li><code>3</code> - 高危</li>
          <li><code>4</code> - 严重</li>
        </ul>

        <h4>示例 1：攻击链关联检测</h4>
        <pre><code>CORRELATE
  EVENT attack WHERE alarm_type == 1 AND alarm_severity >= 2
  EVENT behavior WHERE alarm_type == 2 AND dst_process_path CONTAINS "cmd.exe"
  JOIN ON attack.dst_ip == behavior.terminal_ip
  WINDOW 10m
  GENERATE
    SEVERITY 3
    NAME "检测到攻击链活动"
    DESCRIPTION "网络攻击后发现可疑主机行为"</code></pre>

        <h4>示例 2：横向移动检测</h4>
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

        <h4>示例 3：APT攻击场景关联</h4>
        <pre><code>CORRELATE
  EVENT sample WHERE alarm_type == 3 AND apt_group != ""
  EVENT c2 WHERE alarm_subtype == 1020 AND alarm_name CONTAINS "C2"
  EVENT exfil WHERE alarm_name REGEX ".*数据泄露.*"
  JOIN ON sample.terminal_ip == c2.src_ip 
       AND c2.src_ip == exfil.src_ip
  WINDOW 60m
  GENERATE
    SEVERITY 4
    NAME "APT攻击活动检测"
    DESCRIPTION "检测到完整的APT攻击链：恶意样本 -> C2通信 -> 数据泄露"</code></pre>

        <h4>示例 4：漏洞利用后行为检测</h4>
        <pre><code>CORRELATE
  EVENT exploit WHERE vul_type != "" AND cve_id != ""
  EVENT proc WHERE src_process_path REGEX ".*(powershell|cmd|wscript).*"
  JOIN ON exploit.attacked_ip == proc.terminal_ip
  WINDOW 5m
  GENERATE
    SEVERITY 3
    NAME "漏洞利用成功"
    DESCRIPTION "漏洞利用后检测到可疑进程执行"</code></pre>

        <h4>示例 5：多源攻击同一目标</h4>
        <pre><code>CORRELATE
  EVENT scan WHERE alarm_subtype IN (1001, 1002)
  EVENT brute WHERE alarm_subtype == 1010
  EVENT exploit WHERE alarm_severity >= 3
  JOIN ON scan.dst_ip == brute.dst_ip 
       AND brute.dst_ip == exploit.attacked_ip
  WINDOW 120m
  GENERATE
    SEVERITY 4
    NAME "协同攻击检测"
    DESCRIPTION "检测到扫描、暴力破解、漏洞利用的完整攻击流程"</code></pre>
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

const dslExample = `CORRELATE
  EVENT attack WHERE alarm_type == 1 AND alarm_severity >= 2
  EVENT behavior WHERE alarm_type == 2 AND dst_process_path CONTAINS "cmd.exe"
  JOIN ON attack.dst_ip == behavior.terminal_ip
  WINDOW 10m
  GENERATE
    SEVERITY 3
    NAME "检测到攻击链活动"
    DESCRIPTION "网络攻击后发现可疑主机行为"`

const loadRules = () => {
  // TODO: 调用 API 加载关联规则
  // 示例数据
  rules.value = [
    { 
      id: 1, 
      name: '攻击链关联检测', 
      dsl_rule: 'CORRELATE EVENT attack WHERE alarm_type == 1 EVENT behavior WHERE alarm_type == 2 JOIN ON attack.dst_ip == behavior.terminal_ip WINDOW 10m GENERATE SEVERITY 3 NAME "攻击链活动"',
      enabled: true 
    },
    { 
      id: 2, 
      name: '横向移动检测', 
      dsl_rule: 'CORRELATE EVENT login WHERE alarm_subtype == 2001 EVENT lateral WHERE alarm_subtype == 1005 JOIN ON login.user_account == lateral.user_account WINDOW 30m GENERATE SEVERITY 4 NAME "横向移动"',
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
    const response = await fetch('/api/rules/correlation/compile', {
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
        message: result.message || 'DSL 规则语法正确，可以正常使用。已验证规则结构、事件定义、关联条件和字段名称。'
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
.correlation-rule-container {
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

