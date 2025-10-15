<template>
  <div class="auto-config-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>自动化配置</span>
        </div>
      </template>
      <el-empty description="功能开发中">
        <el-button type="primary">开始配置</el-button>
      </el-empty>
    </el-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
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
</style>

