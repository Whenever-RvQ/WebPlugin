/**
 * Background Script - 后台服务脚本
 * 负责处理网络请求拦截、恶意URL检测、数据管理等核心功能
 */

console.log('🛡️ Web Security Guardian Background Service Starting...')

// 简化的安全管理器
class SimpleSecurityManager {
  private maliciousUrls = new Set([
    'malware-example.com',
    'phishing-test.net',
    'suspicious-site.org',
    'fake-bank.com',
    'scam-lottery.net'
  ])

  private trackerDomains = new Set([
    'google-analytics.com',
    'googletagmanager.com',
    'facebook.com',
    'doubleclick.net',
    'googlesyndication.com',
    'amazon-adsystem.com'
  ])

  isMalicious(url: string): boolean {
    try {
      const hostname = new URL(url).hostname.toLowerCase()
      return Array.from(this.maliciousUrls).some(malicious => 
        hostname === malicious || hostname.endsWith('.' + malicious)
      )
    } catch {
      return false
    }
  }

  isTracker(url: string): boolean {
    try {
      const hostname = new URL(url).hostname.toLowerCase()
      return Array.from(this.trackerDomains).some(tracker => 
        hostname === tracker || hostname.endsWith('.' + tracker)
      )
    } catch {
      return false
    }
  }
}

const securityManager = new SimpleSecurityManager()

// 监听插件安装
chrome.runtime.onInstalled.addListener((details) => {
  console.log('✅ Extension installed:', details.reason)
  
  if (details.reason === 'install') {
    // 初始化存储
    chrome.storage.local.set({
      protection_settings: {
        maliciousUrlProtection: true,
        xssProtection: true,
        trackerBlocking: true,
        formProtection: true,
        phishingProtection: true,
        notifications: true,
        autoUpdate: true,
        strictMode: false
      },
      security_stats: {
        totalThreats: 0,
        blockedThreats: 0,
        allowedThreats: 0,
        threatsByType: {
          malicious_url: 0,
          xss_attack: 0,
          tracker: 0,
          insecure_form: 0,
          suspicious_script: 0,
          phishing: 0
        },
        threatsByLevel: {
          low: 0,
          medium: 0,
          high: 0,
          critical: 0
        },
        lastScanTime: 0
      },
      whitelist: [],
      blacklist: []
    })
    
    // 打开欢迎页面
    chrome.tabs.create({
      url: chrome.runtime.getURL('src/options/index.html')
    })
  }
})

// 监听网络请求（基本版本）
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // 检查恶意URL
    if (securityManager.isMalicious(details.url)) {
      console.log('🚫 Malicious URL detected (blocked by declarativeNetRequest):', details.url)
      
      // 更新统计
      chrome.storage.local.get(['security_stats'], (result) => {
        if (result.security_stats) {
          const stats = result.security_stats
          stats.totalThreats++
          stats.blockedThreats++
          stats.threatsByType.malicious_url++
          stats.threatsByLevel.high++
          chrome.storage.local.set({ security_stats: stats })
        }
      })
    }

    // 检查追踪器
    if (securityManager.isTracker(details.url)) {
      console.log('👁️ Tracker request detected (blocked by declarativeNetRequest):', details.url)
      
      // 更新统计
      chrome.storage.local.get(['security_stats'], (result) => {
        if (result.security_stats) {
          const stats = result.security_stats
          stats.totalThreats++
          stats.blockedThreats++
          stats.threatsByType.tracker++
          stats.threatsByLevel.medium++
          chrome.storage.local.set({ security_stats: stats })
        }
      })
    }
  },
  { urls: ['<all_urls>'] }
)

// 监听消息
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('📨 Received message:', request.type)
  
  try {
    switch (request.type) {
      case 'GET_SECURITY_STATUS':
        chrome.storage.local.get(['security_stats'], (result) => {
          sendResponse({
            maliciousUrlsCount: result.security_stats?.blockedThreats || 0,
            trackersBlocked: result.security_stats?.threatsByType?.tracker || 0
          })
        })
        return true
        
      case 'GET_STATS':
        chrome.storage.local.get(['security_stats'], (result) => {
          sendResponse(result.security_stats || {
            totalThreats: 0,
            blockedThreats: 0,
            allowedThreats: 0,
            threatsByType: {},
            threatsByLevel: {},
            lastScanTime: Date.now()
          })
        })
        return true
        
      case 'UPDATE_SETTINGS':
        chrome.storage.local.set({ protection_settings: request.data }, () => {
          sendResponse({ success: true })
        })
        return true
        
      case 'SETTINGS_UPDATED':
        console.log('⚙️ Settings updated:', request.data)
        sendResponse({ success: true })
        break
        
      case 'TOGGLE_PROTECTION':
        console.log('🔄 Protection toggled:', request.data)
        sendResponse({ success: true })
        break
        
      case 'SCAN_PAGE':
        console.log('🔍 Scanning page:', request.data?.tabId)
        sendResponse({ success: true })
        break
        
      case 'PAGE_NAVIGATION':
        console.log('🔄 Page navigation detected, clearing previous threats for:', request.url)
        
        // 获取当前页面的hostname
        let hostname = ''
        try {
          hostname = new URL(request.url).hostname
        } catch {
          hostname = request.url
        }
        
        // 清除该页面的历史威胁
        chrome.storage.local.get(['threat_history'], (result) => {
          const allThreats = result.threat_history || []
          
          // 过滤掉该页面的威胁，保留其他页面的威胁
          const filteredThreats = allThreats.filter((threat: any) => {
            try {
              const threatHostname = new URL(threat.url).hostname
              return threatHostname !== hostname
            } catch {
              return !threat.url.includes(hostname)
            }
          })
          
          console.log(`🗑️ Cleared ${allThreats.length - filteredThreats.length} threats for ${hostname}`)
          
          // 保存过滤后的威胁
          chrome.storage.local.set({ threat_history: filteredThreats }, () => {
            sendResponse({ success: true, clearedCount: allThreats.length - filteredThreats.length })
          })
        })
        return true
        
      case 'THREAT_DETECTED':
        console.log('🚨 Threat detected:', request.threat || request.data)
        
        const threat = request.threat || request.data
        
        // 更新统计数据
        chrome.storage.local.get(['security_stats', 'threat_history'], (result) => {
          const stats = result.security_stats || {
            totalThreats: 0,
            blockedThreats: 0,
            allowedThreats: 0,
            threatsByType: {
              malicious_url: 0,
              xss_attack: 0,
              sql_injection: 0,
              tracker: 0,
              insecure_form: 0,
              suspicious_script: 0,
              phishing: 0,
              data_leak: 0
            },
            threatsByLevel: {
              low: 0,
              medium: 0,
              high: 0,
              critical: 0
            },
            lastScanTime: Date.now()
          }
          
          // 更新总数
          stats.totalThreats++
          if (threat.blocked) {
            stats.blockedThreats++
          } else {
            stats.allowedThreats++
          }
          
          // 更新按类型统计
          if (stats.threatsByType[threat.type] !== undefined) {
            stats.threatsByType[threat.type]++
          }
          
          // 更新按等级统计
          if (stats.threatsByLevel[threat.level] !== undefined) {
            stats.threatsByLevel[threat.level]++
          }
          
          stats.lastScanTime = Date.now()
          
          // 保存威胁记录
          const threats = result.threat_history || []
          threats.unshift(threat)
          
          // 只保留最近100条
          if (threats.length > 100) {
            threats.splice(100)
          }
          
          chrome.storage.local.set({ 
            security_stats: stats,
            threat_history: threats 
          })
          
          console.log('📊 Stats updated:', stats)
        })
        
        sendResponse({ success: true })
        break
        
      case 'SECURITY_ISSUE':
        console.log('⚠️ Security issue:', request.issueType, request.data)
        sendResponse({ success: true })
        break
      
      case 'UPDATE_WHITELIST':
        console.log('📝 Updating whitelist:', request.data)
        chrome.storage.local.set({ whitelist: request.data }, () => {
          console.log('✅ Whitelist updated successfully')
          sendResponse({ success: true })
        })
        return true
      
      case 'GET_WHITELIST':
        chrome.storage.local.get(['whitelist'], (result) => {
          console.log('📋 Getting whitelist:', result.whitelist)
          sendResponse({ whitelist: result.whitelist || [] })
        })
        return true
      
      case 'UPDATE_BLACKLIST':
        console.log('📝 Updating blacklist:', request.data)
        chrome.storage.local.set({ blacklist: request.data }, () => {
          console.log('✅ Blacklist updated successfully')
          sendResponse({ success: true })
        })
        return true
      
      case 'GET_BLACKLIST':
        chrome.storage.local.get(['blacklist'], (result) => {
          console.log('📋 Getting blacklist:', result.blacklist)
          sendResponse({ blacklist: result.blacklist || [] })
        })
        return true
        
      default:
        sendResponse({ success: true })
    }
  } catch (error) {
    console.error('❌ Error handling message:', error)
    sendResponse({ error: String(error) })
  }
  
  return true
})

// 监听标签页更新
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    console.log('📄 Page loaded:', tab.url)
    
    // 分析页面URL
    if (securityManager.isMalicious(tab.url)) {
      console.log('⚠️ Warning: Potentially malicious page')
    }
  }
})

// 添加安全响应头
// Manifest V3: 响应头修改应通过 declarativeNetRequest 实现，此处仅记录日志
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    console.log('🔐 Headers received from:', details.url)
  },
  { urls: ['<all_urls>'] }
)

console.log('✅ Web Security Guardian Background Service Started Successfully')

// 保持Service Worker活跃
let heartbeatCount = 0
setInterval(() => {
  heartbeatCount++
  console.log(`💓 Service Worker heartbeat #${heartbeatCount}`)
}, 30000) // 每30秒一次