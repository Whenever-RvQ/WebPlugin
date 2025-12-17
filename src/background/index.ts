/**
 * Background Script - 后台服务脚本
 * 负责处理网络请求拦截、恶意URL检测、数据管理等核心功能
 */

console.log('🛡️ Web Security Guardian Background Service Starting...')

// 全局设置存储
let protectionSettings = {
  enabled: true,
  maliciousUrlProtection: true,
  xssProtection: true,
  trackerBlocking: true,
  formProtection: true,
  phishingProtection: true,
  notifications: true,
  autoUpdate: true,
  strictMode: false
}

// 动态规则管理函数
async function updateDeclarativeNetRequestRules() {
  try {
    // 获取当前启用的规则集
    const enabledRulesets = await chrome.declarativeNetRequest.getEnabledRulesets()
    console.log('📋 当前启用的规则集:', enabledRulesets)
    
    const rulesetIds: string[] = []
    
    // 根据设置决定启用哪些规则
    if (protectionSettings.enabled) {
      if (protectionSettings.maliciousUrlProtection) {
        rulesetIds.push('malicious_urls')
      }
      if (protectionSettings.trackerBlocking) {
        rulesetIds.push('tracker_blocking')
      }
    }
    
    // 需要禁用的规则集
    const toDisable = enabledRulesets.filter(id => !rulesetIds.includes(id))
    // 需要启用的规则集
    const toEnable = rulesetIds.filter(id => !enabledRulesets.includes(id))
    
    if (toDisable.length > 0 || toEnable.length > 0) {
      await chrome.declarativeNetRequest.updateEnabledRulesets({
        disableRulesetIds: toDisable,
        enableRulesetIds: toEnable
      })
      console.log('✅ 规则集已更新:', { 已启用: rulesetIds, 已禁用: toDisable, 新启用: toEnable })
    } else {
      console.log('ℹ️ 规则集无需更新')
    }
  } catch (error) {
    console.error('❌ 更新规则集失败:', error)
  }
}

// 从存储中加载设置
chrome.storage.local.get(['protection_settings'], async (result) => {
  if (result.protection_settings) {
    protectionSettings = { ...protectionSettings, ...result.protection_settings }
    console.log('✅ Protection settings loaded:', protectionSettings)
  }
  // 初始化时更新规则
  await updateDeclarativeNetRequestRules()
})

// 监听设置变化
chrome.storage.onChanged.addListener(async (changes, areaName) => {
  if (areaName === 'local' && changes.protection_settings) {
    protectionSettings = changes.protection_settings.newValue
    console.log('⚙️ Protection settings updated:', protectionSettings)
    // 设置变化时更新规则
    await updateDeclarativeNetRequestRules()
  }
})

// 简化的安全管理器
class SimpleSecurityManager {
  private maliciousUrls = new Set([
    // 基本测试URL
    'malware-example.com',
    'phishing-test.net',
    'suspicious-site.org',
    'fake-bank.com',
    'scam-lottery.net',
    // 恶意软件相关
    'malware-download.com',
    'virus-test.org',
    'trojan-horse.net',
    'ransomware-test.com',
    'spyware-domain.org',
    // 钓鱼网站相关
    'paypal-verify.com',
    'apple-security.net',
    'microsoft-update.org',
    'amazon-account.com',
    'google-verify.net',
    'facebook-security.com',
    'netflix-payment.net',
    'bank-verify.org',
    // 诈骗相关
    'free-money.com',
    'win-prize.net',
    'get-rich-quick.org',
    'bitcoin-doubler.com',
    'lottery-winner.net',
    'inheritance-claim.org',
    // 测试域名
    'exploit-kit.invalid',
    'evil-domain.test',
    'malicious-ads.test'
  ])

  private trackerDomains = new Set([
    'google-analytics.com',
    'googletagmanager.com',
    'facebook.com',
    'doubleclick.net',
    'googlesyndication.com',
    'amazon-adsystem.com',
    'connect.facebook.net',
    'www.google-analytics.com',
    'analytics.google.com',
    'stats.g.doubleclick.net',
    'googleads.g.doubleclick.net'
  ])

  isMalicious(url: string): boolean {
    try {
      const urlObj = new URL(url)
      const hostname = urlObj.hostname.toLowerCase()
      const pathname = urlObj.pathname.toLowerCase()
      const fullUrl = url.toLowerCase()
      
      // 1. 检查完全匹配
      if (this.maliciousUrls.has(hostname)) {
        return true
      }
      
      // 2. 检查子域名匹配
      for (const malicious of this.maliciousUrls) {
        if (hostname === malicious || hostname.endsWith('.' + malicious)) {
          return true
        }
      }
      
      // 3. 检查常见钓鱼关键词组合
      const phishingPatterns = [
        /paypal.*verify/i,
        /paypal.*secure/i,
        /paypal.*account/i,
        /amazon.*verify/i,
        /amazon.*account/i,
        /google.*verify/i,
        /google.*security/i,
        /microsoft.*update/i,
        /microsoft.*security/i,
        /apple.*security/i,
        /facebook.*security/i,
        /netflix.*payment/i,
        /bank.*verify/i,
        /secure.*login/i,
        /account.*suspended/i,
        /verify.*identity/i,
        /update.*payment/i,
        /confirm.*account/i,
        /bitcoin.*doubler/i,
        /free.*money/i,
        /win.*prize/i,
        /lottery.*winner/i
      ]
      
      for (const pattern of phishingPatterns) {
        if (pattern.test(hostname) || pattern.test(fullUrl)) {
          console.log('🎣 检测到钓鱼模式:', pattern, 'URL:', url)
          return true
        }
      }
      
      // 4. 检查可疑路径
      const suspiciousPaths = [
        '/malware',
        '/virus',
        '/trojan',
        '/exploit',
        '/payload',
        '/ransomware',
        '/keylogger',
        '/backdoor'
      ]
      
      for (const path of suspiciousPaths) {
        if (pathname.includes(path)) {
          console.log('🚨 检测到可疑路径:', path, 'URL:', url)
          return true
        }
      }
      
      // 5. 检查可疑文件扩展名
      const suspiciousExtensions = [
        '.exe',
        '.scr',
        '.bat',
        '.cmd',
        '.vbs',
        '.js',
        '.jar',
        '.apk'
      ]
      
      for (const ext of suspiciousExtensions) {
        if (pathname.endsWith(ext)) {
          console.log('📦 检测到可疑文件类型:', ext, 'URL:', url)
          return true
        }
      }
      
      return false
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

  // 检查URL是否在用户的黑名单中
  async isInBlacklist(url: string): Promise<boolean> {
    try {
      const hostname = new URL(url).hostname.toLowerCase()
      const result = await chrome.storage.local.get(['blacklist'])
      const blacklist: string[] = result.blacklist || []
      
      return blacklist.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      )
    } catch {
      return false
    }
  }

  // 检查URL是否在用户的白名单中
  async isInWhitelist(url: string): Promise<boolean> {
    try {
      const hostname = new URL(url).hostname.toLowerCase()
      const result = await chrome.storage.local.get(['whitelist'])
      const whitelist: string[] = result.whitelist || []
      
      return whitelist.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      )
    } catch {
      return false
    }
  }

  // 综合URL安全检查
  async checkUrlSecurity(url: string): Promise<{
    isSafe: boolean
    reason: string
    level: 'safe' | 'warning' | 'danger'
  }> {
    // 1. 检查白名单
    if (await this.isInWhitelist(url)) {
      return { isSafe: true, reason: '在白名单中', level: 'safe' }
    }

    // 2. 检查黑名单
    if (await this.isInBlacklist(url)) {
      return { isSafe: false, reason: '在用户黑名单中', level: 'danger' }
    }

    // 3. 检查恶意URL
    if (this.isMalicious(url)) {
      return { isSafe: false, reason: '检测到恶意URL', level: 'danger' }
    }

    // 4. 检查追踪器
    if (this.isTracker(url)) {
      return { isSafe: false, reason: '检测到追踪器', level: 'warning' }
    }

    return { isSafe: true, reason: '未检测到威胁', level: 'safe' }
  }
}

const securityManager = new SimpleSecurityManager()

// 监听插件安装
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('✅ Extension installed:', details.reason)
  
  if (details.reason === 'install') {
    // 初始化存储
    await chrome.storage.local.set({
      protection_settings: {
        enabled: true,  // 总开关默认开启
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
    
    // 初始化 declarativeNetRequest 规则
    await updateDeclarativeNetRequestRules()
    
    // 打开欢迎页面
    chrome.tabs.create({
      url: chrome.runtime.getURL('src/options/index.html')
    })
  } else if (details.reason === 'update') {
    // 扩展更新时也重新初始化规则
    await updateDeclarativeNetRequestRules()
  }
})

// 监听网络请求（基本版本）
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // 检查总开关
    if (!protectionSettings.enabled) {
      return
    }

    // 检查恶意URL（需要恶意URL防护开关开启）
    if (protectionSettings.maliciousUrlProtection && securityManager.isMalicious(details.url)) {
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

      // 显示通知（如果通知开关开启）
      if (protectionSettings.notifications) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: chrome.runtime.getURL('icons/icon.svg'),
          title: '🚫 恶意URL已阻止',
          message: `已拦截恶意网站: ${new URL(details.url).hostname}`,
          priority: 2
        })
      }
    }

    // 检查追踪器（需要追踪阻止开关开启）
    if (protectionSettings.trackerBlocking && securityManager.isTracker(details.url)) {
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
        chrome.storage.local.set({ protection_settings: request.data }, async () => {
          protectionSettings = request.data
          console.log('✅ Settings saved and applied:', protectionSettings)
          // 更新 declarativeNetRequest 规则
          await updateDeclarativeNetRequestRules()
          sendResponse({ success: true })
        })
        return true
        
      case 'GET_SETTINGS':
        chrome.storage.local.get(['protection_settings'], (result) => {
          sendResponse(result.protection_settings || protectionSettings)
        })
        return true
        
      case 'SETTINGS_UPDATED':
        console.log('⚙️ Settings updated:', request.data)
        protectionSettings = request.data
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
        
        // 检查总开关
        if (!protectionSettings.enabled) {
          console.log('⏸️ Protection disabled, threat not recorded')
          sendResponse({ success: false, reason: 'protection_disabled' })
          break
        }
        
        const threat = request.threat || request.data
        
        // 根据威胁类型检查对应的开关
        const shouldProcess = (() => {
          switch (threat.type) {
            case 'malicious_url':
              return protectionSettings.maliciousUrlProtection
            case 'xss_attack':
              return protectionSettings.xssProtection
            case 'tracker':
              return protectionSettings.trackerBlocking
            case 'insecure_form':
              return protectionSettings.formProtection
            case 'phishing':
              return protectionSettings.phishingProtection
            case 'suspicious_script':
              return protectionSettings.xssProtection  // 归类到XSS防护
            default:
              return true
          }
        })()
        
        if (!shouldProcess) {
          console.log(`⏭️ Threat type ${threat.type} protection is disabled`)
          sendResponse({ success: false, reason: 'feature_disabled' })
          break
        }
        
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
          
          // 显示通知（如果通知开关开启且威胁被阻止）
          if (protectionSettings.notifications && threat.blocked) {
            const threatNames: Record<string, string> = {
              malicious_url: '恶意URL',
              xss_attack: 'XSS攻击',
              tracker: '追踪器',
              insecure_form: '不安全表单',
              phishing: '钓鱼网站',
              suspicious_script: '可疑脚本'
            }
            
            chrome.notifications.create({
              type: 'basic',
              iconUrl: chrome.runtime.getURL('icons/icon.svg'),
              title: `🛡️ 已阻止${threatNames[threat.type] || '威胁'}`,
              message: threat.description || `检测到${threatNames[threat.type]}`,
              priority: threat.level === 'critical' || threat.level === 'high' ? 2 : 1
            })
          }
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
      
      case 'CHECK_URL':
        console.log('🔍 Checking URL:', request.url)
        securityManager.checkUrlSecurity(request.url).then((result) => {
          console.log('📊 URL检查结果:', result)
          sendResponse(result)
        }).catch((error) => {
          console.error('❌ URL检查失败:', error)
          sendResponse({ isSafe: true, reason: '检查失败', level: 'safe' })
        })
        return true
      
      case 'PING':
        console.log('🏓 Received PING from content script')
        sendResponse({ success: true, message: 'pong' })
        break
      
      case 'GET_RULES_STATUS':
        chrome.declarativeNetRequest.getEnabledRulesets().then((enabledRulesets) => {
          console.log('📋 当前启用的规则集:', enabledRulesets)
          sendResponse({ 
            enabledRulesets,
            settings: protectionSettings
          })
        }).catch((error) => {
          console.error('❌ 获取规则状态失败:', error)
          sendResponse({ error: String(error) })
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
    
    // 检查总开关和恶意URL防护开关
    if (protectionSettings.enabled && protectionSettings.maliciousUrlProtection) {
      // 分析页面URL
      if (securityManager.isMalicious(tab.url)) {
        console.log('⚠️ Warning: Potentially malicious page')
        
        // 显示警告通知
        if (protectionSettings.notifications) {
          chrome.notifications.create({
            type: 'basic',
            iconUrl: chrome.runtime.getURL('icons/icon.svg'),
            title: '⚠️ 警告：可疑网站',
            message: `您正在访问可能存在安全风险的网站: ${new URL(tab.url).hostname}`,
            priority: 2
          })
        }
      }
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