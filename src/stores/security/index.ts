/**
 * 安全防护状态管理
 */

import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { ThreatLevel } from '@/types'
import type { 
  ProtectionSettings, 
  SecurityStats, 
  ThreatDetection, 
  PageSecurityAnalysis,
  ThreatType
} from '@/types'
import { 
  getSettings, 
  saveSettings, 
  getStats, 
  getThreats, 
  addThreat,
  clearThreats,
  getWhitelist,
  addToWhitelist,
  removeFromWhitelist
} from '@/utils/storage'
import { calculateSecurityScore } from '@/utils/security'

export const useSecurityStore = defineStore('security', () => {
  // 状态
  const settings = ref<ProtectionSettings>({
    enabled: true,  // 总开关默认开启
    maliciousUrlProtection: true,
    xssProtection: true,
    trackerBlocking: true,
    formProtection: true,
    phishingProtection: true,
    notifications: true,
    autoUpdate: true,
    strictMode: false
  })

  const stats = ref<SecurityStats>({
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
  })

  const threats = ref<ThreatDetection[]>([])
  const whitelist = ref<string[]>([])
  const currentPageAnalysis = ref<PageSecurityAnalysis | null>(null)
  const isLoading = ref(false)
  const isActive = ref(true)

  // 计算属性
  const securityScore = computed(() => {
    if (!currentPageAnalysis.value) return 95
    return currentPageAnalysis.value.score
  })

  const recentThreats = computed(() => {
    return threats.value.slice(0, 10)
  })

  const criticalThreats = computed(() => {
    return threats.value.filter(threat => threat.level === ThreatLevel.CRITICAL)
  })

  const blockedThreatsToday = computed(() => {
    const today = new Date()
    today.setHours(0, 0, 0, 0)
    const todayTimestamp = today.getTime()
    
    return threats.value.filter(threat => 
      threat.blocked && threat.timestamp >= todayTimestamp
    ).length
  })

  const protectionStatus = computed(() => {
    if (!isActive.value) return 'disabled'
    const enabledCount = Object.values(settings.value).filter(Boolean).length
    if (enabledCount === 0) return 'disabled'
    if (enabledCount < 4) return 'partial'
    return 'full'
  })

  // 方法
  async function loadSettings() {
    try {
      isLoading.value = true
      settings.value = await getSettings()
    } catch (error) {
      console.error('Failed to load settings:', error)
    } finally {
      isLoading.value = false
    }
  }

  async function updateSettings(newSettings: Partial<ProtectionSettings>) {
    try {
      const updatedSettings = { ...settings.value, ...newSettings }
      await saveSettings(updatedSettings)
      settings.value = updatedSettings
      
      // 通知background script设置已更新
      if (typeof chrome !== 'undefined' && chrome.runtime) {
        chrome.runtime.sendMessage({
          type: 'SETTINGS_UPDATED',
          data: updatedSettings
        })
      }
    } catch (error) {
      console.error('Failed to update settings:', error)
      throw error
    }
  }

  async function loadStats() {
    try {
      stats.value = await getStats()
    } catch (error) {
      console.error('Failed to load stats:', error)
    }
  }

  async function loadThreats() {
    try {
      threats.value = await getThreats()
    } catch (error) {
      console.error('Failed to load threats:', error)
    }
  }

  async function loadWhitelist() {
    try {
      whitelist.value = await getWhitelist()
    } catch (error) {
      console.error('Failed to load whitelist:', error)
    }
  }

  async function addThreatRecord(threat: ThreatDetection) {
    try {
      await addThreat(threat)
      threats.value.unshift(threat)
      
      // 更新统计
      stats.value.totalThreats++
      if (threat.blocked) {
        stats.value.blockedThreats++
      } else {
        stats.value.allowedThreats++
      }
      stats.value.threatsByType[threat.type]++
      stats.value.threatsByLevel[threat.level]++
      stats.value.lastScanTime = Date.now()
    } catch (error) {
      console.error('Failed to add threat record:', error)
      throw error
    }
  }

  async function clearAllThreats() {
    try {
      await clearThreats()
      threats.value = []
      stats.value = {
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
    } catch (error) {
      console.error('Failed to clear threats:', error)
      throw error
    }
  }

  async function addUrlToWhitelist(url: string) {
    try {
      await addToWhitelist(url)
      if (!whitelist.value.includes(url)) {
        whitelist.value.push(url)
      }
    } catch (error) {
      console.error('Failed to add URL to whitelist:', error)
      throw error
    }
  }

  async function removeUrlFromWhitelist(url: string) {
    try {
      await removeFromWhitelist(url)
      const index = whitelist.value.indexOf(url)
      if (index > -1) {
        whitelist.value.splice(index, 1)
      }
    } catch (error) {
      console.error('Failed to remove URL from whitelist:', error)
      throw error
    }
  }

  function updatePageAnalysis(analysis: PageSecurityAnalysis) {
    currentPageAnalysis.value = analysis
  }

  function toggleProtection() {
    isActive.value = !isActive.value
    
    // 通知background script
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'TOGGLE_PROTECTION',
        data: { active: isActive.value }
      })
    }
  }

  async function scanCurrentPage() {
    try {
      if (typeof chrome !== 'undefined' && chrome.tabs) {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
        if (tab.id) {
          chrome.runtime.sendMessage({
            type: 'SCAN_PAGE',
            data: { tabId: tab.id }
          })
        }
      }
    } catch (error) {
      console.error('Failed to scan current page:', error)
      throw error
    }
  }

  // 初始化
  async function initialize() {
    await Promise.all([
      loadSettings(),
      loadStats(),
      loadThreats(),
      loadWhitelist()
    ])
  }

  return {
    // 状态
    settings,
    stats,
    threats,
    whitelist,
    currentPageAnalysis,
    isLoading,
    isActive,
    
    // 计算属性
    securityScore,
    recentThreats,
    criticalThreats,
    blockedThreatsToday,
    protectionStatus,
    
    // 方法
    loadSettings,
    updateSettings,
    loadStats,
    loadThreats,
    loadWhitelist,
    addThreatRecord,
    clearAllThreats,
    addUrlToWhitelist,
    removeUrlFromWhitelist,
    updatePageAnalysis,
    toggleProtection,
    scanCurrentPage,
    initialize
  }
})
