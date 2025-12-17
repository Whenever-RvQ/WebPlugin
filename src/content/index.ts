import { DOMObserver } from './dom-observer'
import { FormMonitor } from './form-monitor'
import { ScriptMonitor } from './script-monitor'
import { PageAnalyzer } from './page-analyzer'
import { detectPhishing, generateThreatId } from '../utils/security'
import { ThreatLevel, ThreatType, type ThreatDetection } from '../types'

declare const chrome: any

/**
 * Content Script - 在网页上下文中运行的实时安全监控器
 */

console.log('🛡️ Web Security Guardian 内容脚本启动:', window.location.href)

const domObserver = new DOMObserver()
const formMonitor = new FormMonitor()
const scriptMonitor = new ScriptMonitor()
const pageAnalyzer = new PageAnalyzer()

const reportedThreatIds = new Set<string>()
const pendingToasts: ThreatDetection[] = []

// 用户交互标志：只有在用户交互后才检测
let hasUserInteracted = false
let interactionTimeout: number | null = null

// 白名单标志
let isWhitelisted = false
// 黑名单标志
let isBlacklisted = false
let blacklistContinue = false // 用户点击继续进入后设为 true

// 保护设置
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

// 从存储中加载设置
chrome.storage.local.get(['protection_settings'], (result) => {
  if (result.protection_settings) {
    protectionSettings = { ...protectionSettings, ...result.protection_settings }
    console.log('✅ Content script settings loaded:', protectionSettings)
  }
})

// 监听设置变化
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && changes.protection_settings) {
    protectionSettings = changes.protection_settings.newValue
    console.log('⚙️ Content script settings updated:', protectionSettings)
  }
})

// ===== 白名单检查 =====

async function checkWhitelist(): Promise<boolean> {
  try {
    const currentHostname = window.location.hostname
    const result = await chrome.storage.local.get(['whitelist'])
    
    // 确保 whitelist 是数组
    let whitelist: string[] = []
    if (result.whitelist && Array.isArray(result.whitelist)) {
      whitelist = result.whitelist
    }
    
    console.log('🔍 白名单检查:', { 当前域名: currentHostname, 白名单数量: whitelist.length })
    
    if (whitelist.length === 0) {
      isWhitelisted = false
      return false
    }
    
    // 检查当前域名是否在白名单中
    isWhitelisted = whitelist.some(domain => 
      currentHostname === domain || currentHostname.endsWith(`.${domain}`)
    )
    
    if (isWhitelisted) {
      console.log('✅ 当前网站在白名单中，已禁用所有安全检测')
      showWhitelistNotification()
    }
    
    return isWhitelisted
  } catch (error) {
    console.error('❌ 检查白名单失败:', error)
    isWhitelisted = false
    return false
    }
}

function showWhitelistNotification() {
  if (!document.body) return
  const notification = document.createElement('div')
  notification.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:linear-gradient(135deg,#667eea,#764ba2);color:white;padding:32px 40px;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.3);z-index:2147483647;text-align:center;min-width:400px'
  notification.innerHTML = '<div style="font-size:48px;margin-bottom:16px">✅</div><h2 style="margin:0 0 12px;font-size:24px;font-weight:700">白名单网站</h2><p style="margin:0 0 24px;font-size:14px;opacity:0.8">当前网站已加入白名单<br>所有安全检测功能已禁用</p><button onclick="this.parentElement.remove()" style="background:rgba(255,255,255,0.2);border:2px solid rgba(255,255,255,0.4);color:white;padding:12px 32px;border-radius:8px;font-size:14px;cursor:pointer">我知道了</button>'
  const overlay = document.createElement('div')
  overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:2147483646'
  overlay.onclick = () => { notification.remove(); overlay.remove() }
  document.body.appendChild(overlay)
  document.body.appendChild(notification)
  setTimeout(() => { if (notification.parentElement) { notification.remove(); overlay.remove() } }, 3000)
}

// ===== 黑名单检查 =====

async function checkBlacklist(): Promise<boolean> {
  try {
    const currentHostname = window.location.hostname
    const result = await chrome.storage.local.get(['blacklist'])
    
    // 确保 blacklist 是数组
    let blacklist: string[] = []
    if (result.blacklist && Array.isArray(result.blacklist)) {
      blacklist = result.blacklist
    }
    
    console.log('🔍 黑名单检查:', { 当前域名: currentHostname, 黑名单数量: blacklist.length })
    
    if (blacklist.length === 0) {
      isBlacklisted = false
      return false
    }
    
    // 检查当前域名是否在黑名单中
    isBlacklisted = blacklist.some(domain => 
      currentHostname === domain || currentHostname.endsWith(`.${domain}`)
    )

    if (isBlacklisted) {
      console.log('⚠️ 当前网站在黑名单中，显示警告弹窗')
      return true
    }
    
    return false
  } catch (error) {
    console.error('❌ 检查黑名单失败:', error)
    isBlacklisted = false
    return false
  }
}

function showBlacklistWarning(): Promise<boolean> {
  return new Promise((resolve) => {
    if (!document.body) {
      resolve(false)
      return
    }
    
    // 创建全屏遮罩
    const overlay = document.createElement('div')
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);z-index:2147483646;backdrop-filter:blur(10px)'
    
    // 创建警告弹窗
    const warning = document.createElement('div')
    warning.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:linear-gradient(135deg,#ff416c,#ff4b2b);color:white;padding:48px;border-radius:24px;box-shadow:0 30px 90px rgba(255,65,108,0.5);z-index:2147483647;text-align:center;width:550px;max-width:90vw;animation:warningPulse 2s ease-in-out infinite'
    
    // 添加脉冲动画
    const style = document.createElement('style')
    style.textContent = `
      @keyframes warningPulse {
        0%, 100% { box-shadow: 0 30px 90px rgba(255,65,108,0.5); }
        50% { box-shadow: 0 30px 90px rgba(255,65,108,0.8), 0 0 40px rgba(255,65,108,0.6); }
      }
    `
    document.head.appendChild(style)
    
    warning.innerHTML = `
      <div style="font-size:72px;margin-bottom:20px;animation:shake 0.5s ease-in-out infinite">⚠️</div>
      <h2 style="margin:0 0 16px;font-size:32px;font-weight:900;text-shadow:2px 2px 4px rgba(0,0,0,0.3)">危险网站警告</h2>
      <p style="margin:0 0 32px;font-size:16px;opacity:0.95;line-height:1.6">
        当前网站已被列入黑名单<br>
        <strong style="font-size:18px">可能存在安全风险或恶意内容</strong><br>
        <span style="font-size:14px;opacity:0.8">建议您立即离开此网站</span>
      </p>
      <div style="display:flex;gap:16px;justify-content:center">
        <button id="blacklistExit" style="background:rgba(255,255,255,0.95);color:#ff4b2b;padding:16px 40px;border:none;border-radius:12px;font-size:16px;font-weight:700;cursor:pointer;transition:all 0.3s;box-shadow:0 4px 12px rgba(0,0,0,0.2)">
          🚪 退出网站
        </button>
        <button id="blacklistContinue" style="background:rgba(255,255,255,0.15);border:2px solid rgba(255,255,255,0.5);color:white;padding:16px 40px;border-radius:12px;font-size:16px;font-weight:600;cursor:pointer;transition:all 0.3s">
          ⚡ 继续进入
        </button>
      </div>
      <p style="margin:24px 0 0;font-size:12px;opacity:0.6">
        网站: ${window.location.hostname}
      </p>
    `
    
    // 添加震动动画
    const shakeStyle = document.createElement('style')
    shakeStyle.textContent = `
      @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-5px) rotate(-5deg); }
        75% { transform: translateX(5px) rotate(5deg); }
      }
    `
    document.head.appendChild(shakeStyle)
    
    document.body.appendChild(overlay)
    document.body.appendChild(warning)
    
    // 退出按钮
    const exitBtn = document.getElementById('blacklistExit')
    if (exitBtn) {
      exitBtn.onmouseover = () => {
        exitBtn.style.transform = 'scale(1.05)'
        exitBtn.style.boxShadow = '0 6px 20px rgba(0,0,0,0.3)'
      }
      exitBtn.onmouseout = () => {
        exitBtn.style.transform = 'scale(1)'
        exitBtn.style.boxShadow = '0 4px 12px rgba(0,0,0,0.2)'
      }
      exitBtn.onclick = () => {
        console.log('🚪 用户选择退出黑名单网站')
        warning.remove()
        overlay.remove()
        style.remove()
        shakeStyle.remove()
        // 重定向到默认页面
        window.location.href = 'about:blank'
        resolve(false)
      }
    }
    
    // 继续按钮
    const continueBtn = document.getElementById('blacklistContinue')
    if (continueBtn) {
      continueBtn.onmouseover = () => {
        continueBtn.style.background = 'rgba(255,255,255,0.25)'
        continueBtn.style.transform = 'scale(1.05)'
      }
      continueBtn.onmouseout = () => {
        continueBtn.style.background = 'rgba(255,255,255,0.15)'
        continueBtn.style.transform = 'scale(1)'
      }
      continueBtn.onclick = () => {
        console.log('⚡ 用户选择继续进入黑名单网站')
        warning.remove()
        overlay.remove()
        style.remove()
        shakeStyle.remove()
        blacklistContinue = true
        resolve(true)
      }
    }
  })
}

// ===== 基础工具 =====

function hasChromeRuntime(): boolean {
  return typeof chrome !== 'undefined' && !!chrome.runtime?.sendMessage
}

function notifyBackground(threat: ThreatDetection) {
  if (!hasChromeRuntime()) return
  if (reportedThreatIds.has(threat.id)) return
  reportedThreatIds.add(threat.id)
  chrome.runtime
    .sendMessage({
      type: 'THREAT_DETECTED',
      threat
    })
    .catch((error: unknown) => console.error('Failed to notify background:', error))
}

function getThreatTypeLabel(type: ThreatType): string {
  switch (type) {
    case ThreatType.MALICIOUS_URL:
      return '恶意网址'
    case ThreatType.XSS_ATTACK:
      return 'XSS攻击'
    case ThreatType.SQL_INJECTION:
      return 'SQL注入'
    case ThreatType.TRACKER:
      return '追踪器'
    case ThreatType.INSECURE_FORM:
      return '不安全传输'
    case ThreatType.SUSPICIOUS_SCRIPT:
      return '可疑脚本'
    case ThreatType.PHISHING:
      return '钓鱼风险'
    case ThreatType.DATA_LEAK:
      return '敏感信息泄露'
    default:
      return '安全警告'
  }
}

function getThreatGradient(level: ThreatLevel): string {
  switch (level) {
    case ThreatLevel.CRITICAL:
      return 'linear-gradient(135deg, #ff1744, #b71c1c)'
    case ThreatLevel.HIGH:
      return 'linear-gradient(135deg, #ff6b6b, #d32f2f)'
    case ThreatLevel.MEDIUM:
      return 'linear-gradient(135deg, #ffb74d, #f57c00)'
    case ThreatLevel.LOW:
      return 'linear-gradient(135deg, #66bb6a, #2e7d32)'
    default:
      return 'linear-gradient(135deg, #607d8b, #455a64)'
  }
}

function showThreatToast(threat: ThreatDetection) {
  if (!document.body) {
    pendingToasts.push(threat)
    return
  }

  let hostname = threat.url
  try {
    hostname = new URL(threat.url).hostname
  } catch {
    // ignore
  }

  const containerId = 'wsg-threat-container'
  let container = document.getElementById(containerId)
  if (!container) {
    container = document.createElement('div')
    container.id = containerId
    container.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
      z-index: 2147483647;
      max-width: 380px;
      pointer-events: none;
    `
    document.body.appendChild(container)
  }

  const toast = document.createElement('div')
  toast.style.cssText = `
    display: flex;
    align-items: flex-start;
    gap: 14px;
    padding: 18px 20px;
    border-radius: 16px;
    color: #fff;
    box-shadow: 0 8px 32px rgba(0,0,0,0.12), 0 2px 8px rgba(0,0,0,0.08);
    background: ${getThreatGradient(threat.level)};
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    line-height: 1.5;
    pointer-events: auto;
    position: relative;
    overflow: hidden;
    opacity: 0;
    transform: translateX(400px) scale(0.9);
    transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
    backdrop-filter: blur(10px);
  `

  // 添加光泽效果
  const shine = document.createElement('div')
  shine.style.cssText = `
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
    animation: shine 3s infinite;
  `
  toast.appendChild(shine)

  toast.innerHTML += `
    <div style="font-size: 24px; line-height: 1; animation: bounce 0.6s ease;">🛡️</div>
    <div style="flex: 1; min-width: 0;">
      <div style="font-weight: 700; font-size: 14px; margin-bottom: 6px; letter-spacing: 0.3px;">
        ${getThreatTypeLabel(threat.type)} · ${threat.level.toUpperCase()}
      </div>
      <div style="font-size: 13px; word-break: break-word; line-height: 1.6; opacity: 0.95;">${threat.description}</div>
      <div style="margin-top: 8px; font-size: 11px; opacity: 0.8; font-weight: 500;">
        📍 ${hostname}
      </div>
    </div>
    <button type="button" aria-label="关闭警告"
      style="background: rgba(255,255,255,0.2); border: none; color: #fff; font-size: 20px; cursor: pointer; line-height: 1; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; transition: all 0.2s; flex-shrink: 0;">×</button>
  `
  
  // 添加动画样式
  if (!document.getElementById('wsg-toast-animations')) {
    const style = document.createElement('style')
    style.id = 'wsg-toast-animations'
    style.textContent = `
      @keyframes shine {
        0% { left: -100%; }
        50% { left: 100%; }
        100% { left: 100%; }
      }
      @keyframes bounce {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.2); }
      }
    `
    document.head.appendChild(style)
  }
  
  const closeButton = toast.querySelector('button')
  closeButton?.addEventListener('mouseenter', () => {
    if (closeButton instanceof HTMLElement) {
      closeButton.style.background = 'rgba(255,255,255,0.3)'
      closeButton.style.transform = 'scale(1.1)'
    }
  })
  closeButton?.addEventListener('mouseleave', () => {
    if (closeButton instanceof HTMLElement) {
      closeButton.style.background = 'rgba(255,255,255,0.2)'
      closeButton.style.transform = 'scale(1)'
    }
  })
  closeButton?.addEventListener('click', (event) => {
    event.stopPropagation()
    toast.style.opacity = '0'
    toast.style.transform = 'translateX(400px) scale(0.8)'
    setTimeout(() => toast.remove(), 400)
  })

  container.appendChild(toast)

  // 触发进入动画
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      toast.style.opacity = '1'
      toast.style.transform = 'translateX(0) scale(1)'
    })
  })
  
  // 自动消失
  setTimeout(() => {
    toast.style.opacity = '0'
    toast.style.transform = 'translateX(400px) scale(0.8)'
    setTimeout(() => toast.remove(), 400)
  }, 6000)
}

function flushPendingToasts() {
  if (!pendingToasts.length) return
  const queue = [...pendingToasts]
  pendingToasts.length = 0
  queue.forEach(showThreatToast)
}

function handleThreat(threat: ThreatDetection, options: { notifyBackground?: boolean } = {}) {
  // 如果总开关关闭，直接返回
  if (!protectionSettings.enabled) {
    console.log('⏸️ Protection disabled, threat ignored')
    return
  }

  // 如果在白名单中，直接返回
  if (isWhitelisted) {
    return
  }

  // 根据威胁类型检查对应的开关
  const shouldProcess = (() => {
    switch (threat.type) {
      case ThreatType.MALICIOUS_URL:
        return protectionSettings.maliciousUrlProtection
      case ThreatType.XSS_ATTACK:
        return protectionSettings.xssProtection
      case ThreatType.TRACKER:
        return protectionSettings.trackerBlocking
      case ThreatType.INSECURE_FORM:
        return protectionSettings.formProtection
      case ThreatType.PHISHING:
        return protectionSettings.phishingProtection
      case ThreatType.SUSPICIOUS_SCRIPT:
        return protectionSettings.xssProtection  // 归类到XSS防护
      default:
        return true
    }
  })()

  if (!shouldProcess) {
    console.log(`⏭️ Threat type ${threat.type} protection is disabled`)
    return
  }

  // 改进日志输出格式
  console.warn('🚨 威胁检测:', {
    类型: getThreatTypeLabel(threat.type),
    等级: threat.level.toUpperCase(),
    描述: threat.description,
    详情: threat.details
  })

  // 显示toast弹窗提示（允许重复）（如果通知开关开启）
  if (protectionSettings.notifications) {
    showThreatToast(threat)
  }

  if (options.notifyBackground) {
    notifyBackground(threat)
  }
}

// ===== 基础标识 =====

const marker = document.createElement('meta')
marker.name = 'web-security-guardian'
marker.content = 'active'
document.head?.appendChild(marker)

;(window as any).webSecurityGuardian = {
  version: '1.0.0',
  isActive: true,
  reportThreat: (rawThreat: Partial<ThreatDetection>) => {
    const normalized: ThreatDetection = {
      id: rawThreat.id || generateThreatId(),
      type: rawThreat.type || ThreatType.DATA_LEAK,
      level: rawThreat.level || ThreatLevel.MEDIUM,
      url: rawThreat.url || window.location.href,
      description: rawThreat.description || '检测到未知安全威胁',
      timestamp: rawThreat.timestamp || Date.now(),
      blocked: rawThreat.blocked ?? false,
      details: rawThreat.details
    }
    handleThreat(normalized, { notifyBackground: true })
  }
}

// ===== 辅助检测 =====

function runBaselineChecks() {
  // 检查表单防护开关
  if (!protectionSettings.enabled || !protectionSettings.formProtection) {
    return
  }

  if (
    window.location.protocol !== 'https:' &&
    window.location.hostname !== 'localhost' &&
    !window.location.hostname.startsWith('127.0.0.')
  ) {
    const threat: ThreatDetection = {
      id: generateThreatId(),
      type: ThreatType.INSECURE_FORM,
      level: ThreatLevel.MEDIUM,
      url: window.location.href,
      description: '当前页面未使用HTTPS加密连接，谨慎输入敏感信息',
      timestamp: Date.now(),
      blocked: false
    }
    handleThreat(threat, { notifyBackground: true })
}
}

function evaluateUrlRisk(url: string, source: string): boolean {
  // 检查钓鱼防护开关
  if (!protectionSettings.enabled || !protectionSettings.phishingProtection) {
    return false
  }

  try {
    // 规范化 URL
    const normalizedUrl = new URL(url, window.location.href).href
    const phishingResult = detectPhishing(normalizedUrl)
    if (phishingResult.detected) {
      const threat: ThreatDetection = {
        id: generateThreatId(),
        type: ThreatType.PHISHING,
        level: phishingResult.score >= 80 ? ThreatLevel.CRITICAL : ThreatLevel.HIGH,
        url: normalizedUrl,
        description: `检测到疑似钓鱼链接（来源：${source}）`,
        timestamp: Date.now(),
        blocked: true,
        details: {
          reasons: phishingResult.reasons,
          score: phishingResult.score,
          source
        }
      }
      handleThreat(threat, { notifyBackground: true })
      console.warn('🎣 钓鱼风险详情:', phishingResult.reasons)
      return true
    }
  } catch (error: unknown) {
    console.warn('无法解析URL进行安全检查:', url, error)
  }
  return false
}

function watchForSuspiciousLinks() {
  document.addEventListener(
    'click',
    (event) => {
      if (!(event.target instanceof Element)) return
      const anchor = event.target.closest('a[href]') as HTMLAnchorElement | null
      if (!anchor) return
      const url = anchor.href
      if (evaluateUrlRisk(url, 'anchor_click')) {
        event.preventDefault()
        event.stopImmediatePropagation()
      }
    },
    true
  )
}

function interceptWindowOpen() {
  const originalOpen = window.open
  window.open = function (...args: Parameters<typeof window.open>): ReturnType<typeof window.open> {
    const urlArg = args[0]
    const url = typeof urlArg === 'string' ? urlArg : urlArg?.toString?.()
    if (typeof url === 'string' && evaluateUrlRisk(url, 'window.open')) {
      return null
    }
    return originalOpen.apply(window, args)
  }
}

// ===== 启动监控 =====

async function startAfterDomReady() {
  flushPendingToasts()

  // 检查白名单，如果在白名单中则禁用所有检测
  const inWhitelist = await checkWhitelist()
  if (inWhitelist) {
    console.log('⏸️ 白名单网站，已禁用所有安全检测')
    return
  }

  // 检查黑名单，如果在黑名单中则显示警告
  const inBlacklist = await checkBlacklist()
  if (inBlacklist && !blacklistContinue) {
    console.log('⚠️ 黑名单网站，显示警告弹窗')
    const shouldContinue = await showBlacklistWarning()
    if (!shouldContinue) {
      console.log('🚫 用户拒绝进入黑名单网站')
      return
    }
    console.log('✅ 用户选择继续进入黑名单网站')
  }

  // 通知 background 页面导航，清除该页面的历史威胁
  if (hasChromeRuntime()) {
    chrome.runtime
      .sendMessage({
        type: 'PAGE_NAVIGATION',
        url: window.location.href
      })
      .then((response: any) => {
        if (response?.clearedCount > 0) {
          console.log(`🗑️ 已清除 ${response.clearedCount} 条历史威胁，开始重新评估`)
        }
      })
      .catch((error: unknown) => console.error('Failed to notify page navigation:', error))
  }

  // ===== 监听用户交互，只在交互后启用监控 =====
  let monitorsInitialized = false
  
  function initializeMonitors() {
    if (monitorsInitialized) return
    monitorsInitialized = true
    
    // 启动所有监控器
    domObserver.setThreatCallback((threat) => handleThreat(threat, { notifyBackground: true }))
    domObserver.initialize()
    
    formMonitor.setThreatCallback((threat) => handleThreat(threat, { notifyBackground: true }))
    formMonitor.initialize()
    
    scriptMonitor.setThreatCallback((threat) => handleThreat(threat, { notifyBackground: true }))
    scriptMonitor.initialize()
    
    console.log('✅ 监控器已启动')
  }
  
  function markUserInteraction() {
    // 如果在白名单中，忽略所有交互
    if (isWhitelisted) {
      return
    }
    
    if (!hasUserInteracted) {
      hasUserInteracted = true
      console.log('👆 检测到用户交互，启动监控')
      // 首次交互时初始化监控器
      initializeMonitors()
    }
    
    // 清除之前的超时
    if (interactionTimeout) {
      clearTimeout(interactionTimeout)
    }
    
    // 交互后5秒内保持检测活跃
    interactionTimeout = window.setTimeout(() => {
      hasUserInteracted = false
      console.log('⏸️ 用户交互超时，暂停监控')
    }, 5000)
  }
  
  // 监听所有可能触发危险操作的用户交互
  document.addEventListener('click', markUserInteraction, true)
  document.addEventListener('submit', markUserInteraction, true)
  document.addEventListener('keydown', (e) => {
    // 只监听 Enter 键（可能提交表单）
    if (e.key === 'Enter') {
      markUserInteraction()
    }
  }, true)

  pageAnalyzer.initialize()
  
  // 禁用初始页面分析，避免页面加载时就弹出大量警报
  // pageAnalyzer.analyzePage().then((analysis) => {
  //   if (analysis.threats.length > 0) {
  //     analysis.threats.forEach((threat) => handleThreat(threat, { notifyBackground: true }))
  //   }
  //   if (hasChromeRuntime()) {
  //     chrome.runtime
  //       .sendMessage({
  //         type: 'PAGE_ANALYZED',
  //         analysis
  //       })
  //       .catch((error: unknown) => console.error('Failed to send PAGE_ANALYZED message:', error))
  //   }
  // })

  // 禁用基础检查，避免页面加载时就报告威胁
  // runBaselineChecks()

  // 禁用初始脚本扫描，只监控动态添加的脚本
  // scriptMonitor.scanScripts().then((threats) => {
  //   threats.forEach((threat) => handleThreat(threat, { notifyBackground: true }))
  // })

  // 禁用初始表单扫描，只监控表单提交
  // formMonitor.scanForms().then((threats) => {
  //   threats.forEach((threat) => handleThreat(threat, { notifyBackground: true }))
  // })

  // 监控可疑链接点击
  watchForSuspiciousLinks()

  console.log('✅ Web Security Guardian 内容脚本已激活（实时监控模式）')
}

// ===== 脚本入口 =====

// 拦截 window.open（立即执行，因为不会产生误报）
interceptWindowOpen()

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startAfterDomReady)
} else {
  startAfterDomReady()
}