<template>
  <div class="auto-config-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>自动化配置</span>
        </div>
      </template>
      <div class="content-wrapper">
        <el-tabs v-model="activeTab" tab-position="left" class="config-tabs">
          <el-tab-pane label="过滤规则" name="filter">
            <FilterRule />
          </el-tab-pane>
          <el-tab-pane label="收敛规则" name="convergence">
            <ConvergenceRule />
          </el-tab-pane>
          <el-tab-pane label="关联规则" name="correlation">
            <CorrelationRule />
          </el-tab-pane>
          <el-tab-pane label="标签规则" name="tag-rule">
            <TagRule />
          </el-tab-pane>
          <el-tab-pane label="标签管理" name="tag-management">
            <TagManagement />
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import FilterRule from './autoconfig/FilterRule.vue'
import ConvergenceRule from './autoconfig/ConvergenceRule.vue'
import CorrelationRule from './autoconfig/CorrelationRule.vue'
import TagRule from './autoconfig/TagRule.vue'
import TagManagement from './autoconfig/TagManagement.vue'

const activeTab = ref('filter')
</script>

<style scoped>
.auto-config-container {
  padding: 20px;
  height: 100%;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: bold;
  font-size: 16px;
}

.el-card {
  height: calc(100vh - 140px);
}

.content-wrapper {
  height: calc(100vh - 220px);
  overflow: hidden;
}

.config-tabs {
  height: 100%;
}

.config-tabs :deep(.el-tabs__content) {
  height: 100%;
  overflow-y: auto;
}

.config-tabs :deep(.el-tabs__nav-wrap) {
  width: 150px;
}

.config-tabs :deep(.el-tabs__item) {
  padding: 0 20px;
  height: 50px;
  line-height: 50px;
  font-size: 14px;
}

.config-tabs :deep(.el-tab-pane) {
  height: 100%;
}
</style>

