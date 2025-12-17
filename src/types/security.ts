/**
 * 安全防护相关类型定义
 */

// 威胁类型枚举
export enum ThreatType {
  MALICIOUS_URL = 'malicious_url',
  XSS_ATTACK = 'xss_attack',
  SQL_INJECTION = 'sql_injection',
  TRACKER = 'tracker',
  INSECURE_FORM = 'insecure_form',
  SUSPICIOUS_SCRIPT = 'suspicious_script',
  PHISHING = 'phishing',
  DATA_LEAK = 'data_leak'
}

// 威胁级别
export enum ThreatLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

// 防护状态
export enum ProtectionStatus {
  ENABLED = 'enabled',
  DISABLED = 'disabled',
  PAUSED = 'paused'
}

// 威胁检测结果
export interface ThreatDetection {
  id: string
  type: ThreatType
  level: ThreatLevel
  url: string
  description: string
  timestamp: number
  blocked: boolean
  details?: Record<string, any>
}

// 安全统计
export interface SecurityStats {
  totalThreats: number
  blockedThreats: number
  allowedThreats: number
  threatsByType: Record<ThreatType, number>
  threatsByLevel: Record<ThreatLevel, number>
  lastScanTime: number
}

// 防护设置
export interface ProtectionSettings {
  enabled: boolean  // 总开关
  maliciousUrlProtection: boolean
  xssProtection: boolean
  trackerBlocking: boolean
  formProtection: boolean
  phishingProtection: boolean
  notifications: boolean
  autoUpdate: boolean
  strictMode: boolean
}

// 恶意URL数据
export interface MaliciousUrl {
  url: string
  category: string
  severity: ThreatLevel
  source: string
  addedAt: number
}

// XSS检测模式
export interface XSSPattern {
  id: string
  pattern: RegExp
  description: string
  severity: ThreatLevel
  enabled: boolean
}

// 追踪器信息
export interface TrackerInfo {
  domain: string
  category: string
  company: string
  description: string
  blocked: boolean
}

// 页面安全分析结果
export interface PageSecurityAnalysis {
  url: string
  score: number
  threats: ThreatDetection[]
  recommendations: string[]
  scanTime: number
  isSecure: boolean
}

// 安全事件
export interface SecurityEvent {
  id: string
  type: ThreatType
  level: ThreatLevel
  message: string
  url: string
  timestamp: number
  action: 'blocked' | 'warned' | 'allowed'
  details?: Record<string, any>
}

// Chrome扩展消息类型
export interface ExtensionMessage {
  type: string
  data?: any
  tabId?: number
  timestamp?: number
}

// 内容脚本消息
export interface ContentScriptMessage extends ExtensionMessage {
  type: 'THREAT_DETECTED' | 'PAGE_ANALYZED' | 'FORM_SUBMITTED' | 'SCRIPT_INJECTED'
}

// 后台脚本消息
export interface BackgroundMessage extends ExtensionMessage {
  type: 'GET_STATS' | 'UPDATE_SETTINGS' | 'SCAN_PAGE' | 'BLOCK_URL' | 'GET_THREATS'
}

// 弹窗消息
export interface PopupMessage extends ExtensionMessage {
  type: 'GET_PAGE_INFO' | 'TOGGLE_PROTECTION' | 'CLEAR_STATS' | 'EXPORT_DATA'
}
