import { createRouter, createWebHistory } from 'vue-router'
import NetworkAttack from './views/NetworkAttack.vue'
import MaliciousSample from './views/MaliciousSample.vue'
import HostBehavior from './views/HostBehavior.vue'

const routes = [
  {
    path: '/',
    redirect: '/network-attack'
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
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router

