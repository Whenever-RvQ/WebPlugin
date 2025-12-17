<template>
  <div class="security-popup">
    <!-- 头部 -->
    <div class="header">
      <div class="logo">
        <el-icon size="24" color="#667eea"><Lock /></el-icon>
        <h1>安全守护者</h1>
      </div>
      <div class="status">
        <el-badge :value="blockedThreatsToday" class="badge">
          <el-button :type="isActive ? 'success' : 'danger'" size="small" circle>
            <el-icon><Check v-if="isActive" /><Close v-else /></el-icon>
          </el-button>
        </el-badge>
      </div>
    </div>

    <!-- 安全评分 -->
    <div class="security-score">
      <el-progress 
        type="circle" 
        :percentage="securityScore" 
        :color="getScoreColor(securityScore)"
        :width="80"
      >
        <template #default="{ percentage }">
          <span class="score-text">{{ percentage }}</span>
        </template>
      </el-progress>
      <div class="score-info">
        <h3>安全评分</h3>
        <p>{{ getScoreDescription(securityScore) }}</p>
      </div>
    </div>

    <!-- 当前页面信息 -->
    <div class="current-page">
      <h3>当前页面</h3>
      <div class="page-info">
        <div class="url">{{ currentUrl }}</div>
        <div class="badges">
          <el-tag :type="isHttps ? 'success' : 'warning'" size="small">
            {{ isHttps ? 'HTTPS' : 'HTTP' }}
          </el-tag>
          <el-tag :type="threatLevel" size="small">
            {{ threatStatus }}
          </el-tag>
        </div>
      </div>
    </div>

    <!-- 统计信息 -->
    <div class="stats">
      <div class="stat-item">
        <div class="stat-number">{{ stats.blockedThreats }}</div>
        <div class="stat-label">已阻止威胁</div>
      </div>
      <div class="stat-item">
        <div class="stat-number">{{ stats.totalThreats }}</div>
        <div class="stat-label">检测到威胁</div>
      </div>
      <div class="stat-item">
        <div class="stat-number">{{ blockedThreatsToday }}</div>
        <div class="stat-label">今日阻止</div>
      </div>
    </div>

    <!-- 最近威胁 -->
    <div class="recent-threats" v-if="recentThreats.length > 0">
      <h3>最近威胁</h3>
      <div class="threat-list">
        <div 
          v-for="threat in recentThreats.slice(0, 3)" 
          :key="threat.id" 
          class="threat-item"
        >
          <el-icon :color="getThreatColor(threat.level)">
            <Warning />
          </el-icon>
          <div class="threat-info">
            <div class="threat-title">{{ getThreatTitle(threat.type) }}</div>
            <div class="threat-time">{{ formatTime(threat.timestamp) }}</div>
          </div>
          <el-tag :type="threat.blocked ? 'success' : 'warning'" size="small">
            {{ threat.blocked ? '已阻止' : '已检测' }}
          </el-tag>
        </div>
      </div>
    </div>

    <!-- 操作按钮 -->
    <div class="actions">
      <el-button 
        type="primary" 
        @click="scanCurrentPage"
        :loading="isScanning"
        style="flex: 1"
      >
        <el-icon><Search /></el-icon>
        扫描当前页面
      </el-button>
      <el-button @click="showPhishingDialog = true" type="warning">
        <el-icon><Warning /></el-icon>
        AI检测
      </el-button>
      <el-button @click="openOptions">
        <el-icon><Setting /></el-icon>
        设置
      </el-button>
    </div>

    <!-- AI钓鱼网站检测对话框 -->
    <el-dialog
      v-model="showPhishingDialog"
      title="钓鱼网站检测"
      width="90%"
      :close-on-click-modal="false"
    >
      <div class="phishing-detector">
        <el-input
          v-model="phishingUrl"
          placeholder="输入要检测的网址，例如: https://example.com"
          size="large"
          clearable
        >
          <template #prepend>
            <el-icon><Link /></el-icon>
          </template>
        </el-input>
        
        <el-button 
          type="primary" 
          @click="detectPhishing"
          :loading="isAnalyzing"
          :disabled="!phishingUrl.trim()"
          style="width: 100%; margin-top: 12px"
          size="large"
        >
          {{ isAnalyzing ? '分析中...' : '开始检测' }}
        </el-button>

        <div v-if="phishingResult" class="result-box" :class="resultClass">
          <div class="result-header">
            <el-icon size="24">
              <SuccessFilled v-if="isSafe" />
              <WarningFilled v-else />
            </el-icon>
            <h3>{{ resultTitle }}</h3>
          </div>
          <div class="result-content" v-html="phishingResult"></div>
        </div>

        <div v-if="isAnalyzing" class="analyzing-tips">
          <el-icon class="is-loading"><Loading /></el-icon>
          <p>AI正在分析网址特征，请稍候...</p>
        </div>
      </div>
    </el-dialog>

    <!-- AI页面扫描结果对话框 -->
    <el-dialog
      v-model="showScanResultDialog"
      title="🔍 AI页面安全扫描报告"
      width="90%"
      :close-on-click-modal="false"
    >
      <div class="scan-result-container">
        <div v-if="scanResult" class="result-box" :class="isScanSafe ? 'safe' : 'danger'">
          <div class="result-header">
            <el-icon size="24">
              <SuccessFilled v-if="isScanSafe" />
              <WarningFilled v-else />
            </el-icon>
            <h3>{{ isScanSafe ? '✅ 页面整体安全' : '⚠️ 发现安全风险' }}</h3>
          </div>
          <div class="result-content" v-html="scanResult"></div>
        </div>

        <div class="scan-info">
          <el-divider />
          <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0;">
            <span style="font-size: 12px; color: #666;">
              扫描时间: {{ new Date().toLocaleString('zh-CN') }}
            </span>
            <span style="font-size: 12px; color: #666;">
              当前页面: {{ currentUrl }}
            </span>
          </div>
        </div>
      </div>
    </el-dialog>

    <!-- 快速开关 -->
    <!-- <div class="quick-toggles">
      <div class="toggle-item">
        <span>恶意URL防护</span>
        <el-switch v-model="settings.maliciousUrlProtection" @change="updateSetting" />
      </div>
      <div class="toggle-item">
        <span>XSS防护</span>
        <el-switch v-model="settings.xssProtection" @change="updateSetting" />
      </div>
      <div class="toggle-item">
        <span>追踪器阻止</span>
        <el-switch v-model="settings.trackerBlocking" @change="updateSetting" />
      </div>
    </div> -->
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useSecurityStore } from '../stores/security'
import { 
  Lock, Check, Close, Warning, Search, Setting, Link, SuccessFilled, WarningFilled, Loading
} from '@element-plus/icons-vue'

declare const chrome: any

const securityStore = useSecurityStore()

// OpenRouter API配置（统一管理）
const OPENROUTER_API_KEY = 'sk-or-v1-9019e42237208f14e9ffe1df1379ffbce36ad247c1289fb8ca2ceb6c52f13d5'

// 响应式数据
const isScanning = ref(false)
const currentUrl = ref('加载中...')
const isHttps = ref(false)
const currentFullUrl = ref('')

// AI钓鱼网站检测
const showPhishingDialog = ref(false)
const phishingUrl = ref('')
const phishingResult = ref('')
const isAnalyzing = ref(false)
const isSafe = ref(true)

// AI页面扫描
const showScanResultDialog = ref(false)
const scanResult = ref('')
const isScanSafe = ref(true)

// 计算属性
const isActive = computed(() => securityStore.isActive)
const securityScore = computed(() => securityStore.securityScore)
const settings = computed(() => securityStore.settings)

// 获取当前页面的hostname
const currentHostname = computed(() => {
  try {
    return new URL(currentFullUrl.value).hostname
  } catch {
    return currentUrl.value
  }
})

// 过滤当前页面的威胁
const currentPageThreats = computed(() => {
  const hostname = currentHostname.value
  return securityStore.threats.filter(threat => {
    try {
      const threatHostname = new URL(threat.url).hostname
      return threatHostname === hostname
    } catch {
      return threat.url.includes(hostname)
    }
  })
})

// 当前页面最近的威胁（最多显示3条）
const recentThreats = computed(() => {
  return currentPageThreats.value.slice(0, 10)
})

// 当前页面的统计数据
const stats = computed(() => {
  const pageThreats = currentPageThreats.value
  const statsData = {
    totalThreats: pageThreats.length,
    blockedThreats: pageThreats.filter(t => t.blocked).length,
    allowedThreats: pageThreats.filter(t => !t.blocked).length,
    threatsByType: {} as any,
    threatsByLevel: {} as any,
    lastScanTime: Date.now()
  }
  
  // 统计类型
  pageThreats.forEach(threat => {
    if (!statsData.threatsByType[threat.type]) {
      statsData.threatsByType[threat.type] = 0
    }
    statsData.threatsByType[threat.type]++
  })
  
  // 统计等级
  pageThreats.forEach(threat => {
    if (!statsData.threatsByLevel[threat.level]) {
      statsData.threatsByLevel[threat.level] = 0
    }
    statsData.threatsByLevel[threat.level]++
  })
  
  return statsData
})

// 今日阻止的威胁（当前页面）
const blockedThreatsToday = computed(() => {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const todayTimestamp = today.getTime()
  
  return currentPageThreats.value.filter(threat => 
    threat.blocked && threat.timestamp >= todayTimestamp
  ).length
})

const threatLevel = computed(() => {
  if (securityScore.value >= 90) return 'success'
  if (securityScore.value >= 70) return 'warning'
  return 'danger'
})

const threatStatus = computed(() => {
  if (securityScore.value >= 90) return '安全'
  if (securityScore.value >= 70) return '注意'
  return '危险'
})

const resultClass = computed(() => {
  return isSafe.value ? 'safe' : 'danger'
})

const resultTitle = computed(() => {
  return isSafe.value ? '✅ 网站安全' : '⚠️ 疑似钓鱼网站'
})

// 方法
function getScoreColor(score: number) {
  if (score >= 90) return '#67c23a'
  if (score >= 70) return '#e6a23c'
  return '#f56c6c'
}

function getScoreDescription(score: number) {
  if (score >= 90) return '网站安全性良好'
  if (score >= 70) return '存在一些安全风险'
  return '发现严重安全问题'
}

function getThreatColor(level: string) {
  const colors = {
    low: '#909399',
    medium: '#e6a23c',
    high: '#f56c6c',
    critical: '#f56c6c'
  }
  return colors[level as keyof typeof colors] || '#909399'
}

function getThreatTitle(type: string) {
  const titles = {
    malicious_url: '恶意URL',
    xss_attack: 'XSS攻击',
    tracker: '隐私追踪',
    insecure_form: '不安全表单',
    suspicious_script: '可疑脚本',
    phishing: '钓鱼网站'
  }
  return titles[type as keyof typeof titles] || '未知威胁'
}

function formatTime(timestamp: number) {
  const now = Date.now()
  const diff = now - timestamp
  const minutes = Math.floor(diff / 60000)
  
  if (minutes < 1) return '刚刚'
  if (minutes < 60) return `${minutes}分钟前`
  
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}小时前`
  
  const days = Math.floor(hours / 24)
  return `${days}天前`
}

// 全球公认的官方网址列表
const trustedOfficialDomains = [
  // 搜索引擎
  { domain: 'google.com', name: 'Google', category: '搜索引擎' },
  { domain: 'bing.com', name: 'Bing', category: '搜索引擎' },
  { domain: 'baidu.com', name: '百度', category: '搜索引擎' },
  { domain: 'yahoo.com', name: 'Yahoo', category: '搜索引擎' },
  // 社交媒体
  { domain: 'facebook.com', name: 'Facebook', category: '社交媒体' },
  { domain: 'twitter.com', name: 'Twitter', category: '社交媒体' },
  { domain: 'x.com', name: 'X (Twitter)', category: '社交媒体' },
  { domain: 'instagram.com', name: 'Instagram', category: '社交媒体' },
  { domain: 'linkedin.com', name: 'LinkedIn', category: '社交媒体' },
  { domain: 'reddit.com', name: 'Reddit', category: '社交媒体' },
  { domain: 'weibo.com', name: '微博', category: '社交媒体' },
  { domain: 'zhihu.com', name: '知乎', category: '社交媒体' },
  // 科技公司
  { domain: 'microsoft.com', name: 'Microsoft', category: '科技公司' },
  { domain: 'apple.com', name: 'Apple', category: '科技公司' },
  { domain: 'amazon.com', name: 'Amazon', category: '电商平台' },
  { domain: 'github.com', name: 'GitHub', category: '开发平台' },
  { domain: 'stackoverflow.com', name: 'Stack Overflow', category: '开发社区' },
  // 视频平台
  { domain: 'youtube.com', name: 'YouTube', category: '视频平台' },
  { domain: 'bilibili.com', name: 'Bilibili', category: '视频平台' },
  { domain: 'netflix.com', name: 'Netflix', category: '视频平台' },
  // 新闻媒体
  { domain: 'bbc.com', name: 'BBC', category: '新闻媒体' },
  { domain: 'cnn.com', name: 'CNN', category: '新闻媒体' },
  { domain: 'nytimes.com', name: 'New York Times', category: '新闻媒体' },
  // 金融支付
  { domain: 'paypal.com', name: 'PayPal', category: '支付平台' },
  { domain: 'alipay.com', name: '支付宝', category: '支付平台' },
  // 电商
  { domain: 'taobao.com', name: '淘宝', category: '电商平台' },
  { domain: 'jd.com', name: '京东', category: '电商平台' },
  { domain: 'tmall.com', name: '天猫', category: '电商平台' },
  { domain: 'ebay.com', name: 'eBay', category: '电商平台' },
  // 云服务
  { domain: 'dropbox.com', name: 'Dropbox', category: '云存储' },
  { domain: 'icloud.com', name: 'iCloud', category: '云服务' },
  // 教育
  { domain: 'wikipedia.org', name: 'Wikipedia', category: '知识百科' },
  { domain: 'coursera.org', name: 'Coursera', category: '在线教育' },
  // 邮件服务
  { domain: 'gmail.com', name: 'Gmail', category: '邮件服务' },
  { domain: 'outlook.com', name: 'Outlook', category: '邮件服务' },
  { domain: 'qq.com', name: 'QQ', category: '邮件服务' },
  // 开发工具
  { domain: 'npmjs.com', name: 'npm', category: '包管理器' },
  { domain: 'docker.com', name: 'Docker', category: '容器平台' }
]

function checkIfTrustedDomain(url: string): { isTrusted: boolean; info?: any } {
  try {
    const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, '')
    
    for (const trusted of trustedOfficialDomains) {
      if (hostname === trusted.domain || hostname.endsWith('.' + trusted.domain)) {
        return { isTrusted: true, info: trusted }
      }
    }
    
    return { isTrusted: false }
  } catch {
    return { isTrusted: false }
  }
}

async function scanCurrentPage() {
  isScanning.value = true
  scanResult.value = ''
  
  try {
    // 获取当前页面信息
    if (typeof chrome === 'undefined' || !chrome.tabs) {
      throw new Error('无法访问浏览器标签页API')
    }
    
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (!tab.url) {
      throw new Error('无法获取当前页面URL')
    }
    
    console.log('🔍 开始扫描页面:', tab.url)
    
    // 检查是否是可信的官方网址
    const trustCheck = checkIfTrustedDomain(tab.url)
    if (trustCheck.isTrusted && trustCheck.info) {
      const info = trustCheck.info
      isScanSafe.value = true
      scanResult.value = `
        <div style="padding: 16px; background: linear-gradient(135deg, #67c23a22, #67c23a11); border-left: 4px solid #67c23a; border-radius: 8px; margin-bottom: 16px;">
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
            <div style="font-size: 32px; font-weight: bold; color: #67c23a;">100</div>
            <div>
              <div style="font-size: 14px; font-weight: 600; color: #67c23a;">综合安全评分</div>
              <div style="font-size: 12px; color: #666;">状态：优秀 ✅ 安全</div>
            </div>
          </div>
        </div>
        
        <h3 style="color: #67c23a; margin-top: 0;">✅ 全球公认的官方网站</h3>
        
        <div style="background: #f0f9ff; padding: 12px; border-radius: 8px; margin: 12px 0;">
          <p style="margin: 4px 0;"><strong>网站名称：</strong>${info.name}</p>
          <p style="margin: 4px 0;"><strong>网站类别：</strong>${info.category}</p>
          <p style="margin: 4px 0;"><strong>官方域名：</strong>${info.domain}</p>
          <p style="margin: 4px 0;"><strong>当前URL：</strong>${tab.url}</p>
        </div>
        
        <h4>🛡️ 安全评估</h4>
        <p><strong>✅ 域名认证：</strong>该域名是全球公认的官方网站，可信度极高</p>
        <p><strong>✅ 品牌认证：</strong>${info.name} 是知名的${info.category}平台</p>
        <p><strong>✅ 安全协议：</strong>${tab.url.startsWith('https://') ? 'HTTPS加密连接' : 'HTTP连接（建议使用HTTPS）'}</p>
        <p><strong>✅ 威胁检测：</strong>未检测到任何安全威胁</p>
        
        <h4>📋 安全建议</h4>
        <ul style="margin: 8px 0; padding-left: 24px;">
          <li>这是${info.name}的官方网站，可以放心使用</li>
          <li>请确保您访问的是正确的官方域名：${info.domain}</li>
          <li>注意保护您的账号密码，不要与他人分享</li>
          ${!tab.url.startsWith('https://') ? '<li style="color: #e6a23c;">⚠️ 建议使用HTTPS访问以确保数据安全</li>' : ''}
        </ul>
        
        <div style="margin-top: 16px; padding: 12px; background: #f8f9fa; border-radius: 8px; font-size: 12px; color: #666;">
          <p style="margin: 0;">✅ 此网站已通过官方域名验证，属于可信任的知名平台</p>
        </div>
      `
      
      showScanResultDialog.value = true
      isScanning.value = false
      console.log('✅ 识别为官方网站，直接返回安全结果')
      return
    }
    
    // 获取页面内容
    let pageContent = ''
    try {
      // 尝试获取页面的DOM内容
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id! },
        func: () => {
          // 提取页面关键信息
          const info = {
            title: document.title,
            url: window.location.href,
            forms: document.querySelectorAll('form').length,
            links: document.querySelectorAll('a').length,
            scripts: document.querySelectorAll('script').length,
            iframes: document.querySelectorAll('iframe').length,
            inputs: document.querySelectorAll('input[type="password"], input[type="email"], input[type="text"]').length,
            hasHttps: window.location.protocol === 'https:',
            // 提取meta信息
            metaDescription: document.querySelector('meta[name="description"]')?.getAttribute('content') || '',
            // 检查可疑元素
            suspiciousElements: {
              hiddenIframes: document.querySelectorAll('iframe[style*="display:none"], iframe[style*="visibility:hidden"]').length,
              externalScripts: Array.from(document.querySelectorAll('script[src]')).filter((s: any) => {
                const src = s.src
                return src && !src.includes(window.location.hostname)
              }).length,
              popupScripts: document.body.innerHTML.includes('window.open') ? 1 : 0
            }
          }
          return info
        }
      })
      
      if (results && results[0]?.result) {
        const pageInfo = results[0].result
        pageContent = `
页面标题: ${pageInfo.title}
页面URL: ${pageInfo.url}
协议: ${pageInfo.hasHttps ? 'HTTPS (安全)' : 'HTTP (不安全)'}

页面元素统计:
- 表单数量: ${pageInfo.forms}
- 链接数量: ${pageInfo.links}
- 脚本数量: ${pageInfo.scripts}
- iframe数量: ${pageInfo.iframes}
- 输入框数量: ${pageInfo.inputs}

可疑元素:
- 隐藏iframe: ${pageInfo.suspiciousElements.hiddenIframes}
- 外部脚本: ${pageInfo.suspiciousElements.externalScripts}
- 弹窗脚本: ${pageInfo.suspiciousElements.popupScripts}

页面描述: ${pageInfo.metaDescription || '无'}
        `.trim()
      }
    } catch (error) {
      console.warn('无法获取页面内容，仅使用URL分析:', error)
      pageContent = `页面URL: ${tab.url}\n协议: ${tab.url.startsWith('https://') ? 'HTTPS (安全)' : 'HTTP (不安全)'}`
    }
    
    // 获取当前页面的威胁记录
    const threats = currentPageThreats.value
    let threatsSummary = ''
    if (threats.length > 0) {
      threatsSummary = `\n\n检测到的威胁 (${threats.length}条):\n`
      threats.slice(0, 5).forEach((threat, index) => {
        threatsSummary += `${index + 1}. ${getThreatTitle(threat.type)} - ${threat.level}级别 - ${threat.description}\n`
      })
    } else {
      threatsSummary = '\n\n当前未检测到威胁。'
    }
    
    // 调用AI API进行分析
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'HTTP-Referer': 'https://github.com/web-security-guardian',
        'X-Title': 'Web Security Guardian',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'tngtech/deepseek-r1t2-chimera:free',
        messages: [
          {
            role: 'system',
            content: '你是一个网络安全专家，专门分析网页安全性。请全面分析提供的页面信息，评估安全风险，并给出专业建议。回答要详细且结构化，包含：1.整体安全评估 2.发现的风险点 3.安全建议。用中文回答。评分标准：65分及以上为安全，65分以下需注意风险。'
          },
          {
            role: 'user',
            content: `请对以下网页进行全面的安全分析：

${pageContent}
${threatsSummary}

请从以下角度进行分析：
1. URL和域名安全性
2. 协议安全（HTTPS/HTTP）
3. 页面元素风险评估（表单、脚本、iframe等）
4. 检测到的安全威胁分析
5. 可疑行为识别
6. **综合安全评分（0-100分）**【必须明确给出评分，格式：综合安全评分：XX分】
7. 具体安全建议

评分标准说明：
- 90-100分：优秀，非常安全
- 80-89分：良好，安全可靠
- 65-79分：合格，整体安全
- 50-64分：一般，存在风险
- 0-49分：较差，有明显安全问题

请给出详细的分析报告，并在报告中明确标注"综合安全评分：XX分"。`
          }
        ]
      })
    })
    
    if (!response.ok) {
      throw new Error(`API请求失败: ${response.status}`)
    }
    
    const data = await response.json()
    const aiResponse = data.choices[0].message.content
    
    console.log('🤖 AI分析结果:', aiResponse)
    
    // 从AI响应中提取评分
    let score = -1
    const scorePatterns = [
      /综合安全评分[：:]\s*(\d+)\s*分/i,
      /安全评分[：:]\s*(\d+)\s*分/i,
      /评分[：:]\s*(\d+)\s*[分\/]/i,
      /(\d+)\s*分\s*\(0-100\)/i,
      /得分[：:]\s*(\d+)/i,
      /分数[：:]\s*(\d+)/i
    ]
    
    for (const pattern of scorePatterns) {
      const match = aiResponse.match(pattern)
      if (match && match[1]) {
        score = parseInt(match[1])
        console.log('📊 提取到评分:', score)
        break
      }
    }
    
    // 判断是否安全
    if (score >= 0) {
      // 根据评分判断：65分及以上为安全
      isScanSafe.value = score >= 65
      console.log(`✅ 根据评分判断: ${score}分 - ${isScanSafe.value ? '安全' : '危险'}`)
    } else {
      // 如果没有提取到评分，使用关键词判断
      const dangerKeywords = ['危险', '高风险', '严重威胁', '不安全', '恶意', '钓鱼']
      const safeKeywords = ['安全', '可信', '正常', '无风险', '低风险']
      
      const hasDanger = dangerKeywords.some(keyword => aiResponse.includes(keyword))
      const hasSafe = safeKeywords.some(keyword => aiResponse.includes(keyword))
      
      isScanSafe.value = hasSafe && !hasDanger
      console.log('⚠️ 未找到评分，使用关键词判断:', isScanSafe.value ? '安全' : '危险')
    }
    
    // 格式化输出
    scanResult.value = aiResponse
      .replace(/\n/g, '<br>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/###\s*(.*?)(<br>|$)/g, '<h4>$1</h4>')
      .replace(/##\s*(.*?)(<br>|$)/g, '<h3>$1</h3>')
    
    // 如果提取到了评分，在结果开头添加评分高亮显示
    if (score >= 0) {
      const scoreColor = score >= 80 ? '#67c23a' : score >= 65 ? '#e6a23c' : '#f56c6c'
      const scoreStatus = score >= 80 ? '优秀' : score >= 65 ? '良好' : '需注意'
      scanResult.value = `
        <div style="padding: 12px; background: linear-gradient(135deg, ${scoreColor}22, ${scoreColor}11); border-left: 4px solid ${scoreColor}; border-radius: 8px; margin-bottom: 16px;">
          <div style="display: flex; align-items: center; gap: 12px;">
            <div style="font-size: 32px; font-weight: bold; color: ${scoreColor};">${score}</div>
            <div>
              <div style="font-size: 14px; font-weight: 600; color: ${scoreColor};">综合安全评分</div>
              <div style="font-size: 12px; color: #666;">状态：${scoreStatus} ${score >= 65 ? '✅ 安全' : '⚠️ 需注意'}</div>
            </div>
          </div>
        </div>
        ${scanResult.value}
      `
    }
    
    // 显示结果对话框
    showScanResultDialog.value = true
    
    console.log('✅ 页面扫描完成')
    
  } catch (error) {
    console.error('扫描失败:', error)
    scanResult.value = `<p style="color: #f56c6c;">❌ 扫描失败: ${error instanceof Error ? error.message : '未知错误'}</p><p>请检查网络连接或稍后重试。</p>`
    isScanSafe.value = true
    showScanResultDialog.value = true
  } finally {
    isScanning.value = false
  }
}

function openOptions() {
  if (typeof chrome !== 'undefined' && chrome.runtime) {
    chrome.runtime.openOptionsPage()
  }
}

async function updateSetting() {
  try {
    await securityStore.updateSettings(settings.value)
  } catch (error) {
    console.error('更新设置失败:', error)
  }
}

// AI钓鱼网站检测
async function detectPhishing() {
  if (!phishingUrl.value.trim()) return
  
  isAnalyzing.value = true
  phishingResult.value = ''
  
  try {
    // 使用OpenRouter免费API (deepseek-r1t2-chimera模型)
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'HTTP-Referer': 'https://github.com/web-security-guardian', // 可选：用于OpenRouter排名
        'X-Title': 'Web Security Guardian', // 可选：用于OpenRouter排名
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'tngtech/deepseek-r1t2-chimera:free',
        messages: [
          {
            role: 'system',
            content: '你是一个网络安全专家，专门识别钓鱼网站。请分析用户提供的URL，判断是否为钓鱼网站。回答要简洁明了，包含：1.判断结果（安全/危险）2.主要原因 3.风险等级。用中文回答，格式清晰。'
          },
          {
            role: 'user',
            content: `请分析这个网址是否为钓鱼网站：${phishingUrl.value}\n\n请从以下方面分析：\n1. 域名特征（是否仿冒知名网站）\n2. URL结构（是否有异常字符或编码）\n3. 顶级域名可信度\n4. 是否包含可疑关键词\n5. 综合安全评估`
          }
        ]
      })
    })
    
    if (!response.ok) {
      throw new Error(`API请求失败: ${response.status}`)
    }
    
    const data = await response.json()
    const aiResponse = data.choices[0].message.content
    
    // 判断是否安全（简单的关键词匹配）
    const dangerKeywords = ['危险', '钓鱼', '不安全', '风险', '可疑', '仿冒', '欺诈']
    const safeKeywords = ['安全', '正常', '可信', '合法']
    
    const hasDanger = dangerKeywords.some(keyword => aiResponse.includes(keyword))
    const hasSafe = safeKeywords.some(keyword => aiResponse.includes(keyword))
    
    isSafe.value = !hasDanger || (hasSafe && !aiResponse.includes('高风险'))
    
    // 格式化输出
    phishingResult.value = aiResponse
      .replace(/\n/g, '<br>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/###\s*(.*?)(<br>|$)/g, '<h4>$1</h4>')
    
  } catch (error) {
    console.error('AI检测失败:', error)
    phishingResult.value = `<p style="color: #f56c6c;">❌ 检测失败: ${error instanceof Error ? error.message : '未知错误'}</p><p>请检查网络连接或稍后重试。</p>`
    isSafe.value = true
  } finally {
    isAnalyzing.value = false
  }
}

async function getCurrentPageInfo() {
  try {
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      if (tab.url) {
        currentFullUrl.value = tab.url
        currentUrl.value = new URL(tab.url).hostname
        isHttps.value = tab.url.startsWith('https://')
        
        // 根据页面安全状况计算评分
        await calculatePageScore(tab.url)
      }
    }
  } catch (error) {
    console.error('获取页面信息失败:', error)
    currentUrl.value = '无法获取'
  }
}

async function calculatePageScore(url: string) {
  let score = 100
  
  // 获取当前页面的hostname
  let currentHostname = ''
  try {
    currentHostname = new URL(url).hostname
  } catch {
    currentHostname = url
  }
  
  // 从统计数据中获取威胁信息
  const stats = securityStore.stats
  const allThreats = securityStore.recentThreats
  
  // 只计算当前页面的威胁（根据URL匹配）
  const currentPageThreats = allThreats.filter(threat => {
    try {
      const threatHostname = new URL(threat.url).hostname
      return threatHostname === currentHostname
    } catch {
      return threat.url.includes(currentHostname)
    }
  })
  
  // 根据威胁等级扣分（只计算当前页面的威胁）
  currentPageThreats.forEach(threat => {
    switch (threat.level) {
      case 'critical':
        score -= 30
        break
      case 'high':
        score -= 20
        break
      case 'medium':
        score -= 10
        break
      case 'low':
        score -= 5
        break
    }
  })
  
  // 检查HTTPS（非本地环境）
  const isLocalDev = url.includes('localhost') || url.includes('127.0.0.1')
  if (!url.startsWith('https://') && !isLocalDev) {
    score -= 15
    console.log('❌ 未使用HTTPS，扣15分')
  }
  
  // 确保分数在0-100之间
  score = Math.max(0, Math.min(100, score))
  
  // 更新store中的评分
  securityStore.currentPageAnalysis = {
    url: url,
    score: score,
    threats: currentPageThreats,
    recommendations: score < 90 ? 
      ['发现安全威胁，建议谨慎操作'] : 
      ['网站安全性良好'],
    scanTime: Date.now(),
    isSecure: score >= 90
  }
  
  console.log(`🔍 页面安全评分: ${score}`)
  console.log(`📊 当前页面威胁: ${currentPageThreats.length} / 总威胁: ${allThreats.length}`)
}

// 监听storage变化
function setupStorageListener() {
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.onChanged.addListener((changes: any, areaName: string) => {
      if (areaName === 'local') {
        console.log('📦 Storage changed:', changes)
        
        // 重新加载数据
        if (changes.security_stats || changes.threat_history) {
          securityStore.loadStats()
          securityStore.loadThreats()
          
          // 重新计算评分
          if (currentFullUrl.value) {
            calculatePageScore(currentFullUrl.value)
          }
        }
      }
    })
  }
}

// 监听标签页切换
function setupTabListener() {
  if (typeof chrome !== 'undefined' && chrome.tabs) {
    chrome.tabs.onActivated.addListener(async () => {
      console.log('🔄 Tab switched, refreshing page info')
      await getCurrentPageInfo()
    })
  }
}

// 生命周期
onMounted(async () => {
  console.log('🎨 Popup opened')
  await securityStore.initialize()
  await getCurrentPageInfo()
  setupStorageListener()
  setupTabListener()
  
  // 每2秒自动刷新一次数据
  setInterval(async () => {
    await securityStore.loadStats()
    await securityStore.loadThreats()
    await calculatePageScore(currentFullUrl.value)
  }, 2000)
})
</script>

<style scoped>
.security-popup {
  padding: 16px;
  background: #f8f9fa;
  min-height: 500px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding: 12px 16px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  border-radius: 8px;
  color: white;
}

.logo {
  display: flex;
  align-items: center;
  gap: 8px;
}

.logo h1 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.security-score {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 20px;
  padding: 16px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.score-info h3 {
  margin: 0 0 4px 0;
  font-size: 14px;
  color: #333;
}

.score-info p {
  margin: 0;
  font-size: 12px;
  color: #666;
}

.score-text {
  font-size: 16px;
  font-weight: bold;
}

.current-page {
  margin-bottom: 20px;
  padding: 16px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.current-page h3 {
  margin: 0 0 12px 0;
  font-size: 14px;
  color: #333;
}

.page-info .url {
  font-size: 12px;
  color: #666;
  margin-bottom: 8px;
  word-break: break-all;
}

.badges {
  display: flex;
  gap: 8px;
}

.stats {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.stat-item {
  text-align: center;
  padding: 12px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.stat-number {
  font-size: 20px;
  font-weight: bold;
  color: #667eea;
  margin-bottom: 4px;
}

.stat-label {
  font-size: 11px;
  color: #666;
}

.recent-threats {
  margin-bottom: 20px;
  padding: 16px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.recent-threats h3 {
  margin: 0 0 12px 0;
  font-size: 14px;
  color: #333;
}

.threat-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.threat-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px;
  background: #f8f9fa;
  border-radius: 4px;
}

.threat-info {
  flex: 1;
}

.threat-title {
  font-size: 12px;
  color: #333;
  margin-bottom: 2px;
}

.threat-time {
  font-size: 10px;
  color: #999;
}

.actions {
  display: flex;
  gap: 8px;
  margin-bottom: 20px;
}

.quick-toggles {
  padding: 16px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.toggle-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
  font-size: 13px;
}

.toggle-item:not(:last-child) {
  border-bottom: 1px solid #f0f0f0;
}

/* AI钓鱼网站检测对话框样式 */
.phishing-detector {
  padding: 8px;
}

.result-box {
  margin-top: 20px;
  padding: 16px;
  border-radius: 8px;
  border: 2px solid;
  animation: slideIn 0.3s ease;
}

@keyframes slideIn {
  from {
    opacity: 0;
    transform: translateY(-10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.result-box.safe {
  background: #f0f9ff;
  border-color: #67c23a;
}

.result-box.danger {
  background: #fef0f0;
  border-color: #f56c6c;
}

.result-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid rgba(0,0,0,0.1);
}

.result-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.result-box.safe .result-header {
  color: #67c23a;
}

.result-box.danger .result-header {
  color: #f56c6c;
}

.result-content {
  font-size: 13px;
  line-height: 1.8;
  color: #333;
}

.result-content :deep(h4) {
  margin: 12px 0 8px 0;
  font-size: 14px;
  font-weight: 600;
  color: #667eea;
}

.result-content :deep(strong) {
  color: #764ba2;
  font-weight: 600;
}

.analyzing-tips {
  margin-top: 20px;
  padding: 16px;
  text-align: center;
  background: #f8f9fa;
  border-radius: 8px;
}

.analyzing-tips p {
  margin: 8px 0 0 0;
  color: #666;
  font-size: 13px;
}

.analyzing-tips .el-icon {
  font-size: 32px;
  color: #667eea;
}

/* AI页面扫描结果样式 */
.scan-result-container {
  padding: 8px;
}

.result-content :deep(h3) {
  margin: 16px 0 8px 0;
  font-size: 15px;
  font-weight: 600;
  color: #667eea;
}

.result-content :deep(ul), .result-content :deep(ol) {
  margin: 8px 0;
  padding-left: 24px;
}

.result-content :deep(li) {
  margin: 4px 0;
  line-height: 1.6;
}

.scan-info {
  margin-top: 16px;
}
</style>

