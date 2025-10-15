import { createRouter, createWebHistory } from 'vue-router'
import NetworkAttack from './views/NetworkAttack.vue'
import MaliciousSample from './views/MaliciousSample.vue'
import HostBehavior from './views/HostBehavior.vue'
import InvalidAlert from './views/InvalidAlert.vue'
import AllAlerts from './views/AllAlerts.vue'

const routes = [
  {
    path: '/',
    redirect: '/all'
  },
  {
    path: '/all',
    name: 'AllAlerts',
    component: AllAlerts,
    meta: { title: '所有告警', standalone: true }
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

