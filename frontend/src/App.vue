<template>
  <div id="app">
    <el-container style="height: 100vh" direction="vertical">
      <!-- 顶部标题栏 -->
      <el-header style="background-color: #304156; height: 60px;">
        <div class="header-top">
          <div class="header-left">
            <h2>告警系统</h2>
            <div class="nav-buttons">
              <el-button 
                :type="activeNav === '/alert-data' ? 'primary' : ''"
                :text="activeNav !== '/alert-data'"
                @click="handleNavSelect('/alert-data')"
                class="nav-btn"
              >
                告警数据
              </el-button>
              <el-button 
                :type="activeNav === '/threat-event' ? 'primary' : ''"
                :text="activeNav !== '/threat-event'"
                @click="handleNavSelect('/threat-event')"
                class="nav-btn"
              >
                威胁事件
              </el-button>
              <el-button 
                :type="activeNav === '/auto-config' ? 'primary' : ''"
                :text="activeNav !== '/auto-config'"
                @click="handleNavSelect('/auto-config')"
                class="nav-btn"
              >
                自动化配置
              </el-button>
            </div>
          </div>
          <!-- <div class="header-right">
            <el-tag type="success">在线</el-tag>
            <span style="margin-left: 15px">{{ currentTime }}</span>
          </div> -->
        </div>
      </el-header>

      <!-- Tab 导航栏 -->
      <!-- <el-header style="background-color: #fff; border-bottom: 1px solid #e6e6e6; height: auto; padding: 0;">
        <el-tabs v-model="activeTab" @tab-click="handleTabClick" class="custom-tabs">
          <el-tab-pane label="精控流量" name="/network-attack"></el-tab-pane>
          <el-tab-pane label="恶意样本" name="/malicious-sample"></el-tab-pane>
          <el-tab-pane label="终端日志" name="/host-behavior"></el-tab-pane>
          <el-tab-pane label="无效告警" name="/invalid-alert"></el-tab-pane>
        </el-tabs>
      </el-header> -->

      <!-- 主内容区 -->
      <el-main style="background-color: #f0f2f5">
        <router-view />
      </el-main>
    </el-container>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'

const router = useRouter()
const route = useRoute()
const currentTime = ref('')
const activeTab = ref('/network-attack')
const activeNav = ref('/alert-data')

const updateTime = () => {
  currentTime.value = new Date().toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

const handleTabClick = (tab) => {
  router.push(tab.paneName)
}

const handleNavSelect = (index) => {
  router.push(index)
}

let timer = null

onMounted(() => {
  updateTime()
  timer = setInterval(updateTime, 1000)
  activeTab.value = route.path
  // 设置顶部导航激活状态
  if (route.meta.standalone) {
    activeNav.value = route.path
  }
})

onUnmounted(() => {
  if (timer) {
    clearInterval(timer)
  }
})

watch(() => route.path, (newPath) => {
  activeTab.value = newPath
  // 更新顶部导航激活状态
  if (route.meta.standalone) {
    activeNav.value = newPath
  }
})
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

#app {
  font-family: 'Helvetica Neue', Helvetica, 'PingFang SC', 'Hiragino Sans GB',
    'Microsoft YaHei', '微软雅黑', Arial, sans-serif;
}

.el-header {
  display: flex;
  align-items: center;
  padding: 0 20px;
}

.header-top {
  width: 100%;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 30px;
}

.header-top h2 {
  color: #fff;
  font-size: 20px;
  margin: 0;
}

.nav-buttons {
  display: flex;
  gap: 10px;
  align-items: center;
}

.nav-btn {
  font-size: 14px;
  height: 36px;
}

.header-right {
  display: flex;
  align-items: center;
  color: #fff;
}

.custom-tabs {
  padding: 0 20px;
}

.custom-tabs .el-tabs__header {
  margin: 0;
}

.el-main {
  padding: 0;
  overflow-y: auto;
}
</style>
