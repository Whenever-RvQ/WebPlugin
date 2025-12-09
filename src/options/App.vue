<template>
  <div class="options-page">
    <div class="header">
      <h1>🛡️ Web Security Guardian 设置</h1>
      <p>配置您的浏览器安全防护选项</p>
    </div>

    <el-tabs v-model="activeTab" class="settings-tabs">
      <!-- 基本设置 -->
      <el-tab-pane label="基本设置" name="general">
        <div class="settings-section">
          <h3>防护功能</h3>
          <div class="setting-group">
            <div class="setting-item">
              <div class="setting-info">
                <h4>恶意URL防护</h4>
                <p>自动检测并阻止访问已知的恶意网站</p>
              </div>
              <el-switch v-model="settings.maliciousUrlProtection" />
            </div>
            
            <div class="setting-item">
              <div class="setting-info">
                <h4>XSS攻击防护</h4>
                <p>检测并阻止跨站脚本攻击</p>
              </div>
              <el-switch v-model="settings.xssProtection" />
            </div>
            
            <div class="setting-item">
              <div class="setting-info">
                <h4>隐私追踪阻止</h4>
                <p>阻止第三方追踪器收集您的数据</p>
              </div>
              <el-switch v-model="settings.trackerBlocking" />
            </div>
            
            <div class="setting-item">
              <div class="setting-info">
                <h4>表单安全检查</h4>
                <p>检查表单提交的安全性</p>
              </div>
              <el-switch v-model="settings.formProtection" />
            </div>
            
            <div class="setting-item">
              <div class="setting-info">
                <h4>钓鱼网站防护</h4>
                <p>识别并警告钓鱼网站</p>
              </div>
              <el-switch v-model="settings.phishingProtection" />
            </div>
          </div>

          <h3>通知设置</h3>
          <div class="setting-group">
            <div class="setting-item">
              <div class="setting-info">
                <h4>安全通知</h4>
                <p>当检测到威胁时显示通知</p>
              </div>
              <el-switch v-model="settings.notifications" />
            </div>
            
            <div class="setting-item">
              <div class="setting-info">
                <h4>严格模式</h4>
                <p>启用更严格的安全检查</p>
              </div>
              <el-switch v-model="settings.strictMode" />
            </div>
          </div>

          <h3>黑白名单管理</h3>
          <div class="setting-group">
            <div class="list-manager">
              <div class="list-section">
                <h4>白名单</h4>
                <p class="list-description">白名单内的网站将被信任，不会进行任何安全检测</p>
                <div class="file-upload-area">
                  <input 
                    ref="whitelistFileInput" 
                    type="file" 
                    accept=".csv" 
                    @change="handleWhitelistUpload"
                    style="display: none;"
                  />
                  <el-button 
                    type="primary" 
                    @click="whitelistFileInput?.click()"
                  >
                    📄 导入白名单 (CSV)
                  </el-button>
                  <span class="file-hint">格式：一行一个网址</span>
                </div>
                <div v-if="whitelist.length > 0" class="list-display">
                  <div class="list-count">已添加 {{ whitelist.length }} 个网址</div>
                  <div class="list-items">
                    <el-tag 
                      v-for="(url, index) in whitelist" 
                      :key="index"
                      closable
                      @close="removeFromWhitelist(index)"
                      class="list-tag"
                    >
                      {{ url }}
                    </el-tag>
                  </div>
                  <el-button 
                    type="danger" 
                    size="small" 
                    @click="clearWhitelist"
                    style="margin-top: 12px;"
                  >
                    清空白名单
                  </el-button>
                </div>
              </div>

              <div class="list-section">
                <h4>黑名单</h4>
                <p class="list-description">黑名单内的网站将被标记（暂不处理）</p>
                <div class="file-upload-area">
                  <input 
                    ref="blacklistFileInput" 
                    type="file" 
                    accept=".csv" 
                    @change="handleBlacklistUpload"
                    style="display: none;"
                  />
                  <el-button 
                    @click="blacklistFileInput?.click()"
                  >
                    📄 导入黑名单 (CSV)
                  </el-button>
                  <span class="file-hint">格式：一行一个网址</span>
                </div>
                <div v-if="blacklist.length > 0" class="list-display">
                  <div class="list-count">已添加 {{ blacklist.length }} 个网址</div>
                  <div class="list-items">
                    <el-tag 
                      v-for="(url, index) in blacklist" 
                      :key="index"
                      closable
                      type="danger"
                      @close="removeFromBlacklist(index)"
                      class="list-tag"
                    >
                      {{ url }}
                    </el-tag>
                  </div>
                  <el-button 
                    type="danger" 
                    size="small" 
                    @click="clearBlacklist"
                    style="margin-top: 12px;"
                  >
                    清空黑名单
                  </el-button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </el-tab-pane>

      <!-- 统计信息 -->
      <el-tab-pane label="统计信息" name="stats">
        <div class="stats-section">
          <div class="stats-cards">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-number">{{ stats.totalThreats }}</div>
                <div class="stat-label">总威胁数</div>
              </div>
            </el-card>
            
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-number">{{ stats.blockedThreats }}</div>
                <div class="stat-label">已阻止</div>
              </div>
            </el-card>
            
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-number">{{ stats.allowedThreats }}</div>
                <div class="stat-label">已允许</div>
              </div>
            </el-card>
          </div>

          <!-- 图表可视化区域 -->
          <div class="charts-grid">
            <!-- 饼图：威胁类型分布 -->
            <el-card class="chart-card">
              <h3>📊 威胁类型分布（饼图）</h3>
              <div ref="pieChartRef" class="chart-container"></div>
            </el-card>

            <!-- 柱状图：威胁类型统计 -->
            <el-card class="chart-card">
              <h3>📈 威胁类型统计（柱状图）</h3>
              <div ref="barChartRef" class="chart-container"></div>
            </el-card>

            <!-- 环形图：威胁等级分布 -->
            <el-card class="chart-card">
              <h3>🎯 威胁等级分布（环形图）</h3>
              <div ref="doughnutChartRef" class="chart-container"></div>
            </el-card>

            <!-- 雷达图：安全防护能力 -->
            <el-card class="chart-card">
              <h3>🛡️ 安全防护能力（雷达图）</h3>
              <div ref="radarChartRef" class="chart-container"></div>
            </el-card>
          </div>

          <!-- 原有的进度条展示 -->
          <el-card class="chart-card" style="margin-top: 20px;">
            <h3>威胁类型详情</h3>
            <div class="threat-types">
              <div v-for="(count, type) in stats.threatsByType" :key="type" class="threat-type-item">
                <span class="threat-type-name">{{ getThreatTypeName(type) }}</span>
                <el-progress :percentage="getThreatPercentage(count)" :color="getThreatColor(type)" />
                <span class="threat-count">{{ getThreatPercentage(count) }}% ({{ count }})</span>
              </div>
            </div>
          </el-card>
        </div>
      </el-tab-pane>

      <!-- 威胁历史 -->
      <el-tab-pane label="威胁历史" name="threats">
        <div class="threats-section">
          <div class="threats-header">
            <h3>最近威胁记录</h3>
            <el-button @click="clearThreats" type="danger" size="small">
              清除历史
            </el-button>
          </div>
          
          <el-table :data="recentThreats" style="width: 100%">
            <el-table-column prop="type" label="类型" width="120">
              <template #default="scope">
                <el-tag :type="getThreatTagType(scope.row.level)" size="small">
                  {{ getThreatTypeName(scope.row.type) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="url" label="URL" min-width="200" show-overflow-tooltip />
            <el-table-column prop="description" label="描述" min-width="150" />
            <el-table-column prop="timestamp" label="时间" width="150">
              <template #default="scope">
                {{ formatDateTime(scope.row.timestamp) }}
              </template>
            </el-table-column>
            <el-table-column prop="blocked" label="状态" width="80">
              <template #default="scope">
                <el-tag :type="scope.row.blocked ? 'success' : 'warning'" size="small">
                  {{ scope.row.blocked ? '已阻止' : '已检测' }}
                </el-tag>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 关于 -->
      <el-tab-pane label="关于" name="about">
        <div class="about-section">
          <el-card>
            <div class="about-content">
              <div class="app-info">
                <h2>🛡️ Web Security Guardian</h2>
                <p class="version">版本 1.0.0</p>
                <p class="description">
                  基于Vue3 + Vite开发的现代化浏览器安全防护插件，
                  为您提供全面的Web应用层安全防护。
                </p>
              </div>
              
              <div class="features">
                <h3>主要功能</h3>
                <ul>
                  <li>🚫 恶意URL检测与阻止</li>
                  <li>⚠️ XSS攻击实时防护</li>
                  <li>👁️ 隐私追踪器阻止</li>
                  <li>🔒 表单安全检查</li>
                  <li>🎣 钓鱼网站识别</li>
                  <li>📊 详细的安全统计</li>
                </ul>
              </div>
              
              <div class="tech-stack">
                <h3>技术栈</h3>
                <div class="tech-tags">
                  <el-tag>Vue 3</el-tag>
                  <el-tag>TypeScript</el-tag>
                  <el-tag>Vite</el-tag>
                  <el-tag>Pinia</el-tag>
                  <el-tag>Element Plus</el-tag>
                  <el-tag>Chrome Extensions API</el-tag>
                </div>
              </div>
            </div>
          </el-card>
        </div>
      </el-tab-pane>
    </el-tabs>

    <div class="footer-actions">
      <el-button @click="saveSettings" type="primary">保存设置</el-button>
      <el-button @click="resetSettings">重置为默认</el-button>
      <el-button @click="exportData">导出数据</el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch, nextTick } from 'vue'
import { ElMessage } from 'element-plus'
import { useSecurityStore } from '../stores/security'
import * as echarts from 'echarts'

declare const chrome: typeof chrome

const securityStore = useSecurityStore()
const activeTab = ref('general')

// 图表引用
const pieChartRef = ref<HTMLElement>()
const barChartRef = ref<HTMLElement>()
const doughnutChartRef = ref<HTMLElement>()
const radarChartRef = ref<HTMLElement>()

let pieChart: echarts.ECharts | null = null
let barChart: echarts.ECharts | null = null
let doughnutChart: echarts.ECharts | null = null
let radarChart: echarts.ECharts | null = null

// 黑白名单
const whitelist = ref<string[]>([])
const blacklist = ref<string[]>([])
const whitelistFileInput = ref<HTMLInputElement>()
const blacklistFileInput = ref<HTMLInputElement>()

// 计算属性
const settings = computed(() => securityStore.settings)
const stats = computed(() => securityStore.stats)
const recentThreats = computed(() => securityStore.recentThreats)

// 方法
function getThreatTypeName(type: string) {
  const names: Record<string, string> = {
    malicious_url: '恶意URL',
    xss_attack: 'XSS攻击',
    tracker: '隐私追踪',
    insecure_form: '不安全表单',
    suspicious_script: '可疑脚本',
    phishing: '钓鱼网站'
  }
  return names[type] || type
}

function getThreatColor(type: string) {
  const colors: Record<string, string> = {
    malicious_url: '#f56c6c',
    xss_attack: '#e6a23c',
    tracker: '#909399',
    insecure_form: '#67c23a',
    suspicious_script: '#409eff',
    phishing: '#f56c6c'
  }
  return colors[type] || '#909399'
}

function getThreatTagType(level: string) {
  const types: Record<string, string> = {
    low: 'info',
    medium: 'warning',
    high: 'danger',
    critical: 'danger'
  }
  return types[level] || 'info'
}

function getThreatPercentage(count: number) {
  const total = stats.value.totalThreats
  return total > 0 ? Math.round((count / total) * 100) : 0
}

function formatDateTime(timestamp: number) {
  return new Date(timestamp).toLocaleString('zh-CN')
}

async function saveSettings() {
  try {
    await securityStore.updateSettings(settings.value)
    ElMessage.success('设置已保存')
  } catch (error) {
    ElMessage.error('保存设置失败')
  }
}

async function resetSettings() {
  try {
    await securityStore.updateSettings({
      maliciousUrlProtection: true,
      xssProtection: true,
      trackerBlocking: true,
      formProtection: true,
      phishingProtection: true,
      notifications: true,
      autoUpdate: true,
      strictMode: false
    })
    ElMessage.success('设置已重置为默认值')
  } catch (error) {
    ElMessage.error('重置设置失败')
  }
}

async function clearThreats() {
  try {
    await securityStore.clearAllThreats()
    ElMessage.success('威胁历史已清除')
  } catch (error) {
    ElMessage.error('清除历史失败')
  }
}

function exportData() {
  // 导出数据功能
  const data = {
    stats: stats.value,
    threats: recentThreats.value,
    settings: settings.value,
    exportTime: new Date().toISOString()
  }
  
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `security-data-${Date.now()}.json`
  a.click()
  URL.revokeObjectURL(url)
  
  ElMessage.success('数据已导出')
}

// 初始化图表
function initCharts() {
  nextTick(() => {
    if (pieChartRef.value) {
      pieChart = echarts.init(pieChartRef.value)
      updatePieChart()
    }
    if (barChartRef.value) {
      barChart = echarts.init(barChartRef.value)
      updateBarChart()
    }
    if (doughnutChartRef.value) {
      doughnutChart = echarts.init(doughnutChartRef.value)
      updateDoughnutChart()
    }
    if (radarChartRef.value) {
      radarChart = echarts.init(radarChartRef.value)
      updateRadarChart()
    }
  })
}

// 更新饼图
function updatePieChart() {
  if (!pieChart) return
  
  const data = Object.entries(stats.value.threatsByType).map(([type, count]) => ({
    name: getThreatTypeName(type),
    value: count
  }))
  
  const option = {
    tooltip: {
      trigger: 'item',
      formatter: '{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      right: 10,
      top: 'center',
      textStyle: {
        fontSize: 12
      }
    },
    series: [
      {
        name: '威胁类型',
        type: 'pie',
        radius: ['0%', '70%'],
        center: ['40%', '50%'],
        data: data,
        emphasis: {
          itemStyle: {
            shadowBlur: 10,
            shadowOffsetX: 0,
            shadowColor: 'rgba(0, 0, 0, 0.5)'
          }
        },
        label: {
          formatter: '{b}\n{d}%'
        },
        color: ['#5470c6', '#91cc75', '#fac858', '#ee6666', '#73c0de', '#3ba272']
      }
    ]
  }
  
  pieChart.setOption(option)
}

// 更新柱状图
function updateBarChart() {
  if (!barChart) return
  
  const types = Object.keys(stats.value.threatsByType).map(type => getThreatTypeName(type))
  const counts = Object.values(stats.value.threatsByType)
  
  const option = {
    tooltip: {
      trigger: 'axis',
      axisPointer: {
        type: 'shadow'
      }
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      data: types,
      axisLabel: {
        interval: 0,
        rotate: 30,
        fontSize: 11
      }
    },
    yAxis: {
      type: 'value',
      name: '数量'
    },
    series: [
      {
        name: '威胁数量',
        type: 'bar',
        data: counts,
        itemStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: '#667eea' },
            { offset: 1, color: '#764ba2' }
          ])
        },
        label: {
          show: true,
          position: 'top'
        }
      }
    ]
  }
  
  barChart.setOption(option)
}

// 更新环形图
function updateDoughnutChart() {
  if (!doughnutChart) return
  
  const data = Object.entries(stats.value.threatsByLevel).map(([level, count]) => ({
    name: getLevelName(level),
    value: count
  }))
  
  const option = {
    tooltip: {
      trigger: 'item',
      formatter: '{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      right: 10,
      top: 'center'
    },
    series: [
      {
        name: '威胁等级',
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['40%', '50%'],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 10,
          borderColor: '#fff',
          borderWidth: 2
        },
        label: {
          show: true,
          formatter: '{b}\n{d}%'
        },
        emphasis: {
          label: {
            show: true,
            fontSize: 16,
            fontWeight: 'bold'
          }
        },
        data: data,
        color: ['#909399', '#e6a23c', '#f56c6c', '#ff4757']
      }
    ]
  }
  
  doughnutChart.setOption(option)
}

// 更新雷达图
function updateRadarChart() {
  if (!radarChart) return
  
  const indicator = [
    { name: '恶意URL防护', max: 100 },
    { name: 'XSS防护', max: 100 },
    { name: '追踪器阻止', max: 100 },
    { name: '表单安全', max: 100 },
    { name: '钓鱼防护', max: 100 },
    { name: '脚本检测', max: 100 }
  ]
  
  // 根据实际阻止率计算防护能力
  const maliciousUrlRate = stats.value.threatsByType.malicious_url 
    ? (stats.value.blockedThreats / stats.value.totalThreats * 100) : 90
  const xssRate = stats.value.threatsByType.xss_attack 
    ? (stats.value.blockedThreats / stats.value.totalThreats * 100) : 85
  const trackerRate = stats.value.threatsByType.tracker 
    ? (stats.value.blockedThreats / stats.value.totalThreats * 100) : 95
  const formRate = stats.value.threatsByType.insecure_form 
    ? (stats.value.blockedThreats / stats.value.totalThreats * 100) : 80
  const phishingRate = stats.value.threatsByType.phishing 
    ? (stats.value.blockedThreats / stats.value.totalThreats * 100) : 88
  const scriptRate = stats.value.threatsByType.suspicious_script 
    ? (stats.value.blockedThreats / stats.value.totalThreats * 100) : 92
  
  const option = {
    tooltip: {
      trigger: 'item'
    },
    radar: {
      indicator: indicator,
      shape: 'polygon',
      splitNumber: 5,
      name: {
        textStyle: {
          fontSize: 12
        }
      },
      splitArea: {
        areaStyle: {
          color: ['rgba(102, 126, 234, 0.1)', 'rgba(102, 126, 234, 0.2)',
                  'rgba(102, 126, 234, 0.3)', 'rgba(102, 126, 234, 0.4)',
                  'rgba(102, 126, 234, 0.5)']
        }
      }
    },
    series: [
      {
        name: '防护能力',
        type: 'radar',
        data: [
          {
            value: [maliciousUrlRate, xssRate, trackerRate, formRate, phishingRate, scriptRate],
            name: '当前防护水平',
            areaStyle: {
              color: 'rgba(102, 126, 234, 0.5)'
            },
            lineStyle: {
              color: '#667eea',
              width: 2
            },
            itemStyle: {
              color: '#667eea'
            }
          }
        ]
      }
    ]
  }
  
  radarChart.setOption(option)
}

function getLevelName(level: string) {
  const names: Record<string, string> = {
    low: '低危',
    medium: '中危',
    high: '高危',
    critical: '严重'
  }
  return names[level] || level
}

// 监听标签页切换，初始化图表
watch(activeTab, (newTab) => {
  if (newTab === 'stats') {
    initCharts()
  }
})

// 监听统计数据变化，更新图表
watch(() => stats.value, () => {
  if (activeTab.value === 'stats') {
    updatePieChart()
    updateBarChart()
    updateDoughnutChart()
    updateRadarChart()
  }
}, { deep: true })

// 黑白名单管理
async function loadLists() {
  try {
    const result = await chrome.storage.local.get(['whitelist', 'blacklist'])
    
    // 确保加载的数据是数组
    whitelist.value = Array.isArray(result.whitelist) ? result.whitelist : []
    blacklist.value = Array.isArray(result.blacklist) ? result.blacklist : []
    
    console.log('📋 加载黑白名单:', {
      whitelist: whitelist.value.length,
      blacklist: blacklist.value.length
    })
  } catch (error) {
    console.error('加载黑白名单失败:', error)
    // 出错时确保初始化为空数组
    whitelist.value = []
    blacklist.value = []
  }
}

async function saveLists() {
  try {
    // 确保保存的是数组
    const whitelistToSave = Array.isArray(whitelist.value) ? whitelist.value : []
    const blacklistToSave = Array.isArray(blacklist.value) ? blacklist.value : []
    
    await chrome.storage.local.set({
      whitelist: whitelistToSave,
      blacklist: blacklistToSave
    })
    
    console.log('💾 保存黑白名单:', {
      whitelist: whitelistToSave.length,
      blacklist: blacklistToSave.length
    })
  } catch (error) {
    console.error('保存黑白名单失败:', error)
    throw error
  }
}

function parseCSV(content: string): string[] {
  try {
    if (!content || typeof content !== 'string') {
      console.error('CSV 内容无效:', content)
      return []
    }
    
    const lines = content.split('\n')
    console.log(`CSV 文件共 ${lines.length} 行`)
    
    const urls = lines
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#')) // 过滤空行和注释
      .map(line => {
        // 清理URL（去除协议前缀，只保留域名）
        try {
          const url = new URL(line.startsWith('http') ? line : `http://${line}`)
          return url.hostname
        } catch {
          // 如果不是有效URL，尝试作为域名处理
          return line.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0]
        }
      })
      .filter(url => url) // 过滤无效项
    
    console.log(`解析出 ${urls.length} 个有效网址`)
    return urls
  } catch (error) {
    console.error('解析 CSV 失败:', error)
    return []
  }
}

async function handleWhitelistUpload(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  
  console.log('📄 白名单上传事件触发', { file: file?.name, size: file?.size })
  
  if (!file) {
    console.warn('没有选择文件')
    return
  }
  
  try {
    console.log('开始读取文件...')
    const content = await file.text()
    console.log('文件读取成功，内容长度:', content.length)
    
    const urls = parseCSV(content)
    console.log('CSV 解析结果:', urls)
    
    if (urls.length === 0) {
      ElMessage.warning('CSV文件为空或格式不正确')
      return
    }
    
    // 确保 whitelist.value 是数组
    const currentWhitelist = Array.isArray(whitelist.value) ? whitelist.value : []
    console.log('当前白名单:', currentWhitelist)
    
    // 合并去重
    const newUrls = [...new Set([...currentWhitelist, ...urls])]
    console.log('合并后白名单:', newUrls)
    
    whitelist.value = newUrls
    await saveLists()
    
    console.log('✅ 白名单保存成功')
    ElMessage.success(`成功导入 ${urls.length} 个白名单网址`)
  } catch (error) {
    console.error('❌ 读取文件失败:', error)
    ElMessage.error(`读取文件失败: ${error instanceof Error ? error.message : '未知错误'}`)
  } finally {
    // 清空input，允许重复选择同一文件
    console.log('清空文件输入框')
    input.value = ''
  }
}

async function handleBlacklistUpload(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  
  console.log('📄 黑名单上传事件触发', { file: file?.name, size: file?.size })
  
  if (!file) {
    console.warn('没有选择文件')
    return
  }
  
  try {
    console.log('开始读取文件...')
    const content = await file.text()
    console.log('文件读取成功，内容长度:', content.length)
    
    const urls = parseCSV(content)
    console.log('CSV 解析结果:', urls)
    
    if (urls.length === 0) {
      ElMessage.warning('CSV文件为空或格式不正确')
      return
    }
    
    // 确保 blacklist.value 是数组
    const currentBlacklist = Array.isArray(blacklist.value) ? blacklist.value : []
    console.log('当前黑名单:', currentBlacklist)
    
    // 合并去重
    const newUrls = [...new Set([...currentBlacklist, ...urls])]
    console.log('合并后黑名单:', newUrls)
    
    blacklist.value = newUrls
    await saveLists()
    
    console.log('✅ 黑名单保存成功')
    ElMessage.success(`成功导入 ${urls.length} 个黑名单网址`)
  } catch (error) {
    console.error('❌ 读取文件失败:', error)
    ElMessage.error(`读取文件失败: ${error instanceof Error ? error.message : '未知错误'}`)
  } finally {
    // 清空input，允许重复选择同一文件
    console.log('清空文件输入框')
    input.value = ''
  }
}

async function removeFromWhitelist(index: number) {
  whitelist.value.splice(index, 1)
  await saveLists()
  ElMessage.success('已从白名单移除')
}

async function removeFromBlacklist(index: number) {
  blacklist.value.splice(index, 1)
  await saveLists()
  ElMessage.success('已从黑名单移除')
}

async function clearWhitelist() {
  whitelist.value = []
  await saveLists()
  ElMessage.success('白名单已清空')
}

async function clearBlacklist() {
  blacklist.value = []
  await saveLists()
  ElMessage.success('黑名单已清空')
}

// 生命周期
onMounted(async () => {
  await securityStore.initialize()
  await loadLists()
  
  // 如果默认打开统计页面，初始化图表
  if (activeTab.value === 'stats') {
    initCharts()
  }
  
  // 监听窗口大小变化，调整图表
  window.addEventListener('resize', () => {
    pieChart?.resize()
    barChart?.resize()
    doughnutChart?.resize()
    radarChart?.resize()
  })
})
</script>

<style scoped>
.options-page {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
  background: #f5f5f5;
  min-height: 100vh;
}

.header {
  text-align: center;
  margin-bottom: 30px;
  padding: 20px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.header h1 {
  margin: 0 0 8px 0;
  color: #333;
}

.header p {
  margin: 0;
  color: #666;
}

.settings-tabs {
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  padding: 20px;
}

.settings-section h3 {
  margin: 0 0 16px 0;
  color: #333;
  border-bottom: 2px solid #667eea;
  padding-bottom: 8px;
}

.setting-group {
  margin-bottom: 24px;
}

.setting-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 0;
  border-bottom: 1px solid #f0f0f0;
}

.setting-item:last-child {
  border-bottom: none;
}

.setting-info h4 {
  margin: 0 0 4px 0;
  color: #333;
  font-size: 14px;
}

.setting-info p {
  margin: 0;
  color: #666;
  font-size: 12px;
}

.list-manager {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
  padding: 16px 0;
}

.list-section h4 {
  margin: 0 0 8px 0;
  color: #333;
  font-size: 16px;
  font-weight: 600;
}

.list-description {
  margin: 0 0 16px 0;
  color: #666;
  font-size: 12px;
  line-height: 1.5;
}

.file-upload-area {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}

.file-hint {
  color: #999;
  font-size: 12px;
}

.list-display {
  background: #f9f9f9;
  border-radius: 8px;
  padding: 16px;
}

.list-count {
  color: #666;
  font-size: 13px;
  margin-bottom: 12px;
  font-weight: 500;
}

.list-items {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  max-height: 300px;
  overflow-y: auto;
}

.list-tag {
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.stats-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
}

.stat-card {
  text-align: center;
}

.stat-content {
  padding: 20px;
}

.stat-number {
  font-size: 32px;
  font-weight: bold;
  color: #667eea;
  margin-bottom: 8px;
}

.stat-label {
  color: #666;
  font-size: 14px;
}

.chart-card {
  margin-top: 20px;
}

.chart-card h3 {
  margin: 0 0 16px 0;
  color: #333;
}

.threat-types {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.threat-type-item {
  display: flex;
  align-items: center;
  gap: 12px;
}

.threat-type-name {
  width: 100px;
  font-size: 12px;
  color: #666;
}

.threat-count {
  min-width: 80px;
  text-align: right;
  font-size: 12px;
  color: #333;
  font-weight: 600;
}

/* 图表网格布局 */
.charts-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 20px;
  margin-bottom: 20px;
}

.chart-container {
  width: 100%;
  height: 350px;
  margin-top: 16px;
}

@media (max-width: 1024px) {
  .charts-grid {
    grid-template-columns: 1fr;
  }
}

.threats-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.threats-header h3 {
  margin: 0;
  color: #333;
}

.about-content {
  text-align: center;
}

.app-info h2 {
  margin: 0 0 8px 0;
  color: #333;
}

.version {
  color: #666;
  margin-bottom: 16px;
}

.description {
  color: #666;
  line-height: 1.6;
  margin-bottom: 24px;
}

.features {
  margin-bottom: 24px;
}

.features h3 {
  margin: 0 0 12px 0;
  color: #333;
}

.features ul {
  list-style: none;
  padding: 0;
  margin: 0;
}

.features li {
  padding: 4px 0;
  color: #666;
}

.tech-stack h3 {
  margin: 0 0 12px 0;
  color: #333;
}

.tech-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
}

.footer-actions {
  margin-top: 20px;
  text-align: center;
  padding: 20px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.footer-actions .el-button {
  margin: 0 8px;
}
</style>
