import { createRouter, createWebHistory } from 'vue-router'
import NetworkAttack from './views/NetworkAttack.vue'
import MaliciousSample from './views/MaliciousSample.vue'
import HostBehavior from './views/HostBehavior.vue'
import InvalidAlert from './views/InvalidAlert.vue'
import AllAlerts from './views/AllAlerts.vue'
import ThreatEvent from './views/ThreatEvent.vue'
import AutoConfig from './views/AutoConfig.vue'

const routes = [
  {
    path: '/',
    redirect: '/alert-data'
  },
  {
    path: '/alert-data',
    name: 'AlertData',
    component: AllAlerts,
    meta: { title: '告警数据', standalone: true }
  },
  {
    path: '/threat-event',
    name: 'ThreatEvent',
    component: ThreatEvent,
    meta: { title: '威胁事件', standalone: true }
  },
  {
    path: '/auto-config',
    name: 'AutoConfig',
    component: AutoConfig,
    meta: { title: '自动化配置', standalone: true }
  },
  // 兼容旧路由
  {
    path: '/all',
    redirect: '/alert-data'
  },
  {
    path: '/network-attack',
    name: 'NetworkAttack',
    component: NetworkAttack,
    meta: { title: '网络攻击' }
  },
  {
    path: '/malicious-sample',
    name: 'MaliciousSample',
    component: MaliciousSample,
    meta: { title: '恶意样本' }
  },
  {
    path: '/host-behavior',
    name: 'HostBehavior',
    component: HostBehavior,
    meta: { title: '主机行为' }
  },
  {
    path: '/invalid-alert',
    name: 'InvalidAlert',
    component: InvalidAlert,
    meta: { title: '无效告警' }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router

