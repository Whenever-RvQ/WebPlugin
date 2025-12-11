/**
 * 表单监控器 - 负责监控表单安全（增强版）
 */

import type { ThreatDetection } from '../types'
import { ThreatLevel, ThreatType } from '../types'
import { detectSensitiveData, detectSQLInjection, detectXSS, isSecureForm } from '../utils/security'

declare const chrome: any

export class FormMonitor {
  private formListeners: Map<HTMLFormElement, EventListener> = new Map()
  
  private threatCallback?: (threat: ThreatDetection) => void
  
  initialize() {
    console.log('📝 Form Monitor initialized')
    this.setupFormMonitoring()
  }
  
  setThreatCallback(callback: (threat: ThreatDetection) => void) {
    this.threatCallback = callback
  }

  private setupFormMonitoring() {
    document.addEventListener(
      'submit',
      (event) => {
        if (event.target instanceof HTMLFormElement) {
          this.onFormSubmit(event as SubmitEvent)
      }
      },
      true
    )
    
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node instanceof HTMLFormElement) {
            this.monitorForm(node)
          } else if (node instanceof HTMLElement) {
            node.querySelectorAll('form').forEach((form) => this.monitorForm(form))
          }
        })
      })
    })
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    })
  }
  
  private monitorForm(form: HTMLFormElement) {
    if (this.formListeners.has(form)) return
    
    const submitHandler: EventListener = (event) => {
      this.onFormSubmit(event as SubmitEvent)
    }
    
    form.addEventListener('submit', submitHandler, true)
    this.formListeners.set(form, submitHandler)
  }
  
  private onFormSubmit(event: SubmitEvent) {
    const form = event.target as HTMLFormElement
    const threats = this.analyzeFormSubmit(form)
    
    if (threats.length === 0) return

    const hasCriticalThreat = threats.some(
      (threat) => threat.level === ThreatLevel.CRITICAL || threat.level === ThreatLevel.HIGH
    )
      
      if (hasCriticalThreat) {
      event.preventDefault()
        this.showWarning(threats)
        this.reportThreats(threats)
    }
  }
  
  private showWarning(threats: ThreatDetection[]) {
    const message = threats.map((threat) => `• ${threat.description}`).join('\n')
    console.warn(`⚠️ 检测到安全威胁：\n\n${message}\n\n为了您的安全，表单提交已被阻止。`)
  }
  
  private reportThreats(threats: ThreatDetection[]) {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime
        .sendMessage({
        type: 'THREAT_DETECTED',
        threats
        })
        .catch((err: unknown) => console.error('Failed to report threats:', err))
    }

    this.emitThreats(threats)
  }

  private emitThreats(threats: ThreatDetection[]) {
    if (!this.threatCallback) return
    threats.forEach((threat) => this.threatCallback?.(threat))
  }

  async scanForms(): Promise<ThreatDetection[]> {
    const threats: ThreatDetection[] = []
    const forms = document.querySelectorAll('form')
    
    forms.forEach((form, index) => {
      const formThreats = this.analyzeForm(form, index)
      threats.push(...formThreats)
    })
    
    return threats
  }

  async checkFormSecurity(form: HTMLFormElement): Promise<boolean> {
    return isSecureForm(form)
  }
  
  private analyzeFormSubmit(form: HTMLFormElement): ThreatDetection[] {
    const threats: ThreatDetection[] = []
    const formData = new FormData(form)
    
    for (const [name, value] of formData.entries()) {
      if (typeof value !== 'string') continue

        const sqlResult = detectSQLInjection(value)
        if (sqlResult.detected) {
        sqlResult.patterns.forEach((pattern) => {
            threats.push({
              id: `sql_injection_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            type: ThreatType.SQL_INJECTION,
              level: pattern.severity,
              url: window.location.href,
              description: `表单字段 "${name}" 包含SQL注入攻击: ${pattern.description}`,
              timestamp: Date.now(),
              blocked: true,
              details: { field: name, value: value.substring(0, 100), pattern: pattern.id }
            })
          })
        }
        
        const xssResult = detectXSS(value)
        if (xssResult.detected) {
        xssResult.patterns.forEach((pattern) => {
            threats.push({
              id: `xss_form_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            type: ThreatType.XSS_ATTACK,
              level: pattern.severity,
              url: window.location.href,
              description: `表单字段 "${name}" 包含XSS攻击: ${pattern.description}`,
              timestamp: Date.now(),
              blocked: true,
              details: { field: name, value: value.substring(0, 100), pattern: pattern.id }
            })
          })
        }
        
        const sensitiveResult = detectSensitiveData(value)
        if (sensitiveResult.detected && !form.action.startsWith('https://')) {
          threats.push({
            id: `sensitive_data_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          type: ThreatType.INSECURE_FORM,
          level: ThreatLevel.HIGH,
            url: window.location.href,
            description: `表单在非HTTPS连接下传输敏感信息: ${sensitiveResult.types.join(', ')}`,
            timestamp: Date.now(),
            blocked: true,
            details: { field: name, types: sensitiveResult.types }
          })
      }
    }
    
    return threats
  }

  private analyzeForm(form: HTMLFormElement, index: number): ThreatDetection[] {
    const threats: ThreatDetection[] = []
    const action = form.action || window.location.href
    const method = form.method.toLowerCase()
    
    if (method === 'post' && !action.startsWith('https://')) {
      const hasPasswordField = form.querySelector('input[type="password"]')
      const hasSensitiveFields = this.hasSensitiveFields(form)
      
      if (hasPasswordField || hasSensitiveFields) {
        threats.push({
          id: `insecure_form_${Date.now()}_${index}`,
          type: ThreatType.INSECURE_FORM,
          level: ThreatLevel.HIGH,
          url: window.location.href,
          description: '表单包含敏感信息但未使用HTTPS提交',
          timestamp: Date.now(),
          blocked: false,
          details: {
            action,
            method,
            hasPassword: !!hasPasswordField,
            hasSensitiveFields
          }
        })
      }
    }
    
    if (action && action !== window.location.href) {
      try {
        const actionUrl = new URL(action)
        const currentUrl = new URL(window.location.href)
        
        if (actionUrl.hostname !== currentUrl.hostname) {
          threats.push({
            id: `cross_domain_form_${Date.now()}_${index}`,
            type: ThreatType.SUSPICIOUS_SCRIPT,
            level: ThreatLevel.MEDIUM,
            url: window.location.href,
            description: `表单提交到外部域名: ${actionUrl.hostname}`,
            timestamp: Date.now(),
            blocked: false,
            details: { action, targetDomain: actionUrl.hostname }
          })
        }
      } catch (error) {
        threats.push({
          id: `invalid_form_action_${Date.now()}_${index}`,
          type: ThreatType.SUSPICIOUS_SCRIPT,
          level: ThreatLevel.MEDIUM,
          url: window.location.href,
          description: '表单action包含无效URL',
          timestamp: Date.now(),
          blocked: false,
          details: { action }
        })
      }
    }
    
    return threats
  }

  private hasSensitiveFields(form: HTMLFormElement): boolean {
    const inputs = form.querySelectorAll('input, textarea')
    const sensitivePatterns = [
      /password/i,
      /credit.*card/i,
      /social.*security/i,
      /ssn/i,
      /银行卡/i,
      /密码/i,
      /身份证/i,
      /phone/i,
      /email/i,
      /address/i
    ]
    
    for (const input of inputs) {
      const element = input as HTMLInputElement | HTMLTextAreaElement
      const fieldText = `${element.name} ${element.placeholder} ${element.id}`.toLowerCase()
      
      if (sensitivePatterns.some((pattern) => pattern.test(fieldText))) {
        return true
      }
      
      if (element instanceof HTMLInputElement) {
        const sensitiveTypes = ['password', 'email', 'tel']
        if (sensitiveTypes.includes(element.type)) {
          return true
        }
      }
    }
    
    return false
  }
}
