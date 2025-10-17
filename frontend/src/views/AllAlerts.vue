<template>
  <div class="all-alerts-container">
    <el-card>
      <el-tabs v-model="activeTab" @tab-click="handleTabClick" class="alerts-tabs">
        <el-tab-pane label="精控流量" name="network-attack">
          <NetworkAttack />
        </el-tab-pane>
        <el-tab-pane label="恶意样本" name="malicious-sample">
          <MaliciousSample />
        </el-tab-pane>
        <el-tab-pane label="终端日志" name="host-behavior">
          <HostBehavior />
        </el-tab-pane>
        <!-- <el-tab-pane label="无效告警" name="invalid-alert">
          <InvalidAlert />
        </el-tab-pane> -->
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import NetworkAttack from './NetworkAttack.vue'
import MaliciousSample from './MaliciousSample.vue'
import HostBehavior from './HostBehavior.vue'
import InvalidAlert from './InvalidAlert.vue'

const route = useRoute()
const router = useRouter()
const activeTab = ref('network-attack')

const handleTabClick = (tab) => {
  // 更新 URL 查询参数
  router.push({ query: { tab: tab.paneName } })
}

// 监听路由变化，从 URL 查询参数中读取当前 tab
watch(() => route.query.tab, (newTab) => {
  if (newTab && ['network-attack', 'malicious-sample', 'host-behavior', 'invalid-alert'].includes(newTab)) {
    activeTab.value = newTab
  }
}, { immediate: true })

onMounted(() => {
  // 如果 URL 中有 tab 参数，使用它；否则默认为第一个 tab
  const tabParam = route.query.tab
  if (tabParam && ['network-attack', 'malicious-sample', 'host-behavior', 'invalid-alert'].includes(tabParam)) {
    activeTab.value = tabParam
  }
})
</script>

<style scoped>
.all-alerts-container {
  padding: 20px;
  height: 100%;
  background-color: #f0f2f5;
}

.alerts-tabs {
  height: 100%;
}

.alerts-tabs :deep(.el-tabs__content) {
  height: calc(100vh - 160px);
  overflow: auto;
}

.alerts-tabs :deep(.el-tab-pane) {
  height: 100%;
}

/* 移除内部组件的 padding，避免双重 padding */
.alerts-tabs :deep(.page-container) {
  padding: 0;
  height: 100%;
}

.alerts-tabs :deep(.el-card) {
  box-shadow: none;
}
</style>

