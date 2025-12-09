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

// 白名单标志：如果当前页面在白名单中，禁用所有检测
let isWhitelisted = false

// ===== 白名单检查 =====

async function checkWhitelist() {
  try {
    const currentHostname = window.location.hostname
    const result = await chrome.storage.local.get(['whitelist'])
    const whitelist: string[] = result.whitelist || []
    
    console.log('🔍 白名单检查:', {
      当前域名: currentHostname,
      白名单数量: whitelist.length,
      白名单内容: whitelist
    })
    
    // 检查当前域名是否在白名单中
    isWhitelisted = whitelist.some(domain => {
      // 完全匹配或者是子域名
      const isMatch = currentHostname === domain || currentHostname.endsWith(`.${domain}`)
      if (isMatch) {
        console.log(`✅ 域名匹配成功: ${currentHostname} 匹配 ${domain}`)
      }
      return isMatch
    })
    
    if (isWhitelisted) {
      console.log('✅ 当前网站在白名单中，已禁用所有安全检测')
      showWhitelistNotification()
      return true
    } else {
      console.log('ℹ️ 当前网站不在白名单中，正常启用安全检测')
    }
    
    return false
  } catch (error) {
    console.error('❌ 检查白名单失败:', error)
    return false
  }
}

function showWhitelistNotification() {
  // 创建白名单提醒弹窗
  const notification = document.createElement('div')
  notification.id = 'wsg-whitelist-notification'
  notification.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 32px 40px;
    border-radius: 16px;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    z-index: 2147483647;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    text-align: center;
    min-width: 400px;
    animation: slideIn 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
  `
  
  notification.innerHTML = `
    <div style="font-size: 48px; margin-bottom: 16px;">✅</div>
    <h2 style="margin: 0 0 12px 0; font-size: 24px; font-weight: 700;">白名单网站</h2>
    <p style="margin: 0 0 8px 0; font-size: 16px; opacity: 0.95;">
      当前网站已加入白名单
    </p>
    <p style="margin: 0 0 24px 0; font-size: 14px; opacity: 0.8;">
      所有安全检测功能已禁用
    </p>
    <button 
      type="button"
      style="
        background: rgba(255, 255, 255, 0.2);
        border: 2px solid rgba(255, 255, 255, 0.4);
        color: white;
        padding: 12px 32px;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s;
      "
      onmouseover="this.style.background='rgba(255,255,255,0.3)'; this.style.transform='scale(1.05)'"
      onmouseout="this.style.background='rgba(255,255,255,0.2)'; this.style.transform='scale(1)'"
      onclick="this.parentElement.style.opacity='0'; this.parentElement.style.transform='translate(-50%, -50%) scale(0.9)'; setTimeout(() => this.parentElement.remove(), 300)"
    >
      我知道了
    </button>
  `
  
  // 添加动画样式
  const style = document.createElement('style')
  style.textContent = `
    @keyframes slideIn {
      0% {
        opacity: 0;
        transform: translate(-50%, -50%) scale(0.8);
      }
      100% {
        opacity: 1;
        transform: translate(-50%, -50%) scale(1);
      }
    }
  `
  document.head.appendChild(style)
  
  // 添加遮罩层
  const overlay = document.createElement('div')
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.5);
    z-index: 2147483646;
    animation: fadeIn 0.3s;
  `
  
  const overlayStyle = document.createElement('style')
  overlayStyle.textContent = `
    @keyframes fadeIn {
      0% { opacity: 0; }
      100% { opacity: 1; }
    }
  `
  document.head.appendChild(overlayStyle)
  
  // 点击遮罩层也可以关闭
  overlay.onclick = () => {
    notification.style.opacity = '0'
    notification.style.transform = 'translate(-50%, -50%) scale(0.9)'
    overlay.style.opacity = '0'
    setTimeout(() => {
      notification.remove()
      overlay.remove()
    }, 300)
  }
  
  document.body.appendChild(overlay)
  document.body.appendChild(notification)
  
  // 3秒后自动关闭
  setTimeout(() => {
    if (notification.parentElement) {
      notification.style.opacity = '0'
      notification.style.transform = 'translate(-50%, -50%) scale(0.9)'
      overlay.style.opacity = '0'
      setTimeout(() => {
        notification.remove()
        overlay.remove()
      }, 300)
    }
  }, 3000)
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
  // 如果在白名单中，直接返回，不处理威胁
  if (isWhitelisted) {
    return
  }

  // 改进日志输出格式
  console.warn('🚨 威胁检测:', {
    类型: getThreatTypeLabel(threat.type),
    等级: threat.level.toUpperCase(),
    描述: threat.description,
    详情: threat.details
  })

  // 显示toast弹窗提示（允许重复）
  showThreatToast(threat)

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