/**
 * 存储工具函数
 */

import browser from 'webextension-polyfill'
import type { ProtectionSettings, SecurityStats, ThreatDetection } from '@/types'

// 默认设置
export const DEFAULT_SETTINGS: ProtectionSettings = {
  maliciousUrlProtection: true,
  xssProtection: true,
  trackerBlocking: true,
  formProtection: true,
  phishingProtection: true,
  notifications: true,
  autoUpdate: true,
  strictMode: false
}

// 默认统计
export const DEFAULT_STATS: SecurityStats = {
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
}

// 存储键名
export const STORAGE_KEYS = {
  SETTINGS: 'protection_settings',
  STATS: 'security_stats',
  THREATS: 'threat_history',
  WHITELIST: 'whitelist',
  BLACKLIST: 'blacklist',
  MALICIOUS_URLS: 'malicious_urls',
  LAST_UPDATE: 'last_update'
} as const

// 获取设置
export async function getSettings(): Promise<ProtectionSettings> {
  try {
    const result = await browser.storage.local.get(STORAGE_KEYS.SETTINGS)
    return { ...DEFAULT_SETTINGS, ...result[STORAGE_KEYS.SETTINGS] }
  } catch (error) {
    console.error('Failed to get settings:', error)
    return DEFAULT_SETTINGS
  }
}

// 保存设置
export async function saveSettings(settings: Partial<ProtectionSettings>): Promise<void> {
  try {
    const currentSettings = await getSettings()
    const newSettings = { ...currentSettings, ...settings }
    await browser.storage.local.set({ [STORAGE_KEYS.SETTINGS]: newSettings })
  } catch (error) {
    console.error('Failed to save settings:', error)
    throw error
  }
}

// 获取统计数据
export async function getStats(): Promise<SecurityStats> {
  try {
    const result = await browser.storage.local.get(STORAGE_KEYS.STATS)
    return { ...DEFAULT_STATS, ...result[STORAGE_KEYS.STATS] }
  } catch (error) {
    console.error('Failed to get stats:', error)
    return DEFAULT_STATS
  }
}

// 保存统计数据
export async function saveStats(stats: Partial<SecurityStats>): Promise<void> {
  try {
    const currentStats = await getStats()
    const newStats = { ...currentStats, ...stats }
    await browser.storage.local.set({ [STORAGE_KEYS.STATS]: newStats })
  } catch (error) {
    console.error('Failed to save stats:', error)
    throw error
  }
}

// 获取威胁历史
export async function getThreats(): Promise<ThreatDetection[]> {
  try {
    const result = await browser.storage.local.get(STORAGE_KEYS.THREATS)
    return result[STORAGE_KEYS.THREATS] || []
  } catch (error) {
    console.error('Failed to get threats:', error)
    return []
  }
}

// 添加威胁记录
export async function addThreat(threat: ThreatDetection): Promise<void> {
  try {
    const threats = await getThreats()
    threats.unshift(threat) // 添加到开头
    
    // 只保留最近1000条记录
    if (threats.length > 1000) {
      threats.splice(1000)
    }
    
    await browser.storage.local.set({ [STORAGE_KEYS.THREATS]: threats })
    
    // 更新统计
    await updateStats(threat)
  } catch (error) {
    console.error('Failed to add threat:', error)
    throw error
  }
}

// 更新统计数据
async function updateStats(threat: ThreatDetection): Promise<void> {
  const stats = await getStats()
  
  stats.totalThreats++
  if (threat.blocked) {
    stats.blockedThreats++
  } else {
    stats.allowedThreats++
  }
  
  stats.threatsByType[threat.type]++
  stats.threatsByLevel[threat.level]++
  stats.lastScanTime = Date.now()
  
  await saveStats(stats)
}

// 清除威胁历史
export async function clearThreats(): Promise<void> {
  try {
    await browser.storage.local.remove(STORAGE_KEYS.THREATS)
    await saveStats(DEFAULT_STATS)
  } catch (error) {
    console.error('Failed to clear threats:', error)
    throw error
  }
}

// 获取白名单
export async function getWhitelist(): Promise<string[]> {
  try {
    const result = await browser.storage.local.get(STORAGE_KEYS.WHITELIST)
    return result[STORAGE_KEYS.WHITELIST] || []
  } catch (error) {
    console.error('Failed to get whitelist:', error)
    return []
  }
}

// 添加到白名单
export async function addToWhitelist(url: string): Promise<void> {
  try {
    const whitelist = await getWhitelist()
    if (!whitelist.includes(url)) {
      whitelist.push(url)
      await browser.storage.local.set({ [STORAGE_KEYS.WHITELIST]: whitelist })
    }
  } catch (error) {
    console.error('Failed to add to whitelist:', error)
    throw error
  }
}

// 从白名单移除
export async function removeFromWhitelist(url: string): Promise<void> {
  try {
    const whitelist = await getWhitelist()
    const index = whitelist.indexOf(url)
    if (index > -1) {
      whitelist.splice(index, 1)
      await browser.storage.local.set({ [STORAGE_KEYS.WHITELIST]: whitelist })
    }
  } catch (error) {
    console.error('Failed to remove from whitelist:', error)
    throw error
  }
}

// 获取黑名单
export async function getBlacklist(): Promise<string[]> {
  try {
    const result = await browser.storage.local.get(STORAGE_KEYS.BLACKLIST)
    return result[STORAGE_KEYS.BLACKLIST] || []
  } catch (error) {
    console.error('Failed to get blacklist:', error)
    return []
  }
}

// 添加到黑名单
export async function addToBlacklist(url: string): Promise<void> {
  try {
    const blacklist = await getBlacklist()
    if (!blacklist.includes(url)) {
      blacklist.push(url)
      await browser.storage.local.set({ [STORAGE_KEYS.BLACKLIST]: blacklist })
    }
  } catch (error) {
    console.error('Failed to add to blacklist:', error)
    throw error
  }
}

// 从黑名单移除
export async function removeFromBlacklist(url: string): Promise<void> {
  try {
    const blacklist = await getBlacklist()
    const index = blacklist.indexOf(url)
    if (index > -1) {
      blacklist.splice(index, 1)
      await browser.storage.local.set({ [STORAGE_KEYS.BLACKLIST]: blacklist })
    }
  } catch (error) {
    console.error('Failed to remove from blacklist:', error)
    throw error
  }
}

// 检查是否在白名单中
export async function isWhitelisted(url: string): Promise<boolean> {
  try {
    const whitelist = await getWhitelist()
    const hostname = new URL(url).hostname
    return whitelist.some(whiteUrl => {
      try {
        const whiteHostname = new URL(whiteUrl).hostname
        return hostname === whiteHostname || hostname.endsWith('.' + whiteHostname)
      } catch {
        return false
      }
    })
  } catch {
    return false
  }
}

// 导出数据
export async function exportData(): Promise<string> {
  try {
    const [settings, stats, threats, whitelist] = await Promise.all([
      getSettings(),
      getStats(),
      getThreats(),
      getWhitelist()
    ])
    
    const data = {
      settings,
      stats,
      threats: threats.slice(0, 100), // 只导出最近100条
      whitelist,
      exportTime: Date.now(),
      version: '1.0.0'
    }
    
    return JSON.stringify(data, null, 2)
  } catch (error) {
    console.error('Failed to export data:', error)
    throw error
  }
}

// 导入数据
export async function importData(jsonData: string): Promise<void> {
  try {
    const data = JSON.parse(jsonData)
    
    if (data.settings) {
      await saveSettings(data.settings)
    }
    
    if (data.whitelist) {
      await browser.storage.local.set({ [STORAGE_KEYS.WHITELIST]: data.whitelist })
    }
    
    // 不导入统计和威胁历史，避免数据混乱
  } catch (error) {
    console.error('Failed to import data:', error)
    throw error
  }
}
