/**
 * 脚本监控器 - 负责监控页面中的脚本安全
 */

import type { ThreatDetection } from '../types'
import { ThreatLevel, ThreatType } from '../types'

declare const chrome: any

export class ScriptMonitor {
  private suspiciousPatterns = [
    /eval\s*\(/gi,
    /document\.write\s*\(/gi,
    /innerHTML\s*=.*<script/gi,
    /location\.href\s*=/gi,
    /window\.open\s*\(/gi,
    /document\.cookie/gi,
    /localStorage\./gi,
    /sessionStorage\./gi
  ]

  private threatCallback?: (threat: ThreatDetection) => void

  initialize() {
    console.log('📜 Script Monitor initialized')
    this.setupRealTimeMonitoring()
    this.interceptDangerousFunctions()
  }

  setThreatCallback(callback: (threat: ThreatDetection) => void) {
    this.threatCallback = callback
  }
  
  // 设置实时监控
  private setupRealTimeMonitoring() {
    // 监控动态添加的脚本
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeName === 'SCRIPT') {
            this.handleDynamicScript(node as HTMLScriptElement)
          }
        })
      })
    })
    
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    })
  }
  
  // 处理动态添加的脚本
  private handleDynamicScript(script: HTMLScriptElement) {
    // 日志已在 handleThreat 中统一输出
    if (script.src) {
      this.analyzeExternalScript(script, 0).forEach(threat => {
        this.reportThreat(threat)
      })
    } else if (script.textContent) {
      this.analyzeInlineScript(script, 0).forEach(threat => {
        this.reportThreat(threat)
      })
    }
  }
  
  // 拦截危险函数（在页面环境中）
  private interceptDangerousFunctions() {
    try {
    const injectedScript = document.createElement('script')
    injectedScript.textContent = `
      (function() {
        // 保存原始函数
        const originalEval = window.eval;
        const originalFunction = window.Function;
        const originalSetTimeout = window.setTimeout;
        const originalSetInterval = window.setInterval;
        
        // 拦截eval
        window.eval = function(...args) {
          console.warn('🚨 eval() 被调用:', args[0]?.substring(0, 100));
          window.postMessage({
            type: 'WEB_SEC_GUARDIAN_ALERT',
            function: 'eval',
            args: args[0]?.substring(0, 200),
            stack: new Error().stack
          }, '*');
          return originalEval.apply(this, args);
        };
        
        // 拦截Function构造函数
        window.Function = new Proxy(originalFunction, {
          construct(target, args) {
            console.warn('🚨 Function() 被调用:', args);
            window.postMessage({
              type: 'WEB_SEC_GUARDIAN_ALERT',
              function: 'Function',
              args: JSON.stringify(args).substring(0, 200),
              stack: new Error().stack
            }, '*');
            return new target(...args);
          }
        });
        
        // 拦截setTimeout中的字符串
        window.setTimeout = function(handler, ...args) {
          if (typeof handler === 'string') {
            console.warn('🚨 setTimeout执行字符串代码:', handler.substring(0, 100));
            window.postMessage({
              type: 'WEB_SEC_GUARDIAN_ALERT',
              function: 'setTimeout',
              args: handler.substring(0, 200)
            }, '*');
          }
          return originalSetTimeout.call(this, handler, ...args);
        };
        
        // 拦截setInterval中的字符串
        window.setInterval = function(handler, ...args) {
          if (typeof handler === 'string') {
            console.warn('🚨 setInterval执行字符串代码:', handler.substring(0, 100));
            window.postMessage({
              type: 'WEB_SEC_GUARDIAN_ALERT',
              function: 'setInterval',
              args: handler.substring(0, 200)
            }, '*');
          }
          return originalSetInterval.call(this, handler, ...args);
        };
        
        console.log('🛡️ Web Security Guardian - 危险函数监控已激活');
      })();
    `;
    
    // 在所有脚本之前注入
    (document.head || document.documentElement).insertBefore(
      injectedScript,
      (document.head || document.documentElement).firstChild
    )
    injectedScript.remove()
    } catch (error) {
      // CSP 阻止了内联脚本注入，这是正常的安全行为
      // 插件的其他检测功能不受影响
    }
    
    // 监听来自页面的消息
    window.addEventListener('message', (event) => {
      if (event.source !== window) return
      if (event.data.type === 'WEB_SEC_GUARDIAN_ALERT') {
        const threat: ThreatDetection = {
          id: `dangerous_function_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          type: ThreatType.XSS_ATTACK,
          level: ThreatLevel.HIGH,
          url: window.location.href,
          description: `检测到危险函数调用: ${event.data.function}()`,
          timestamp: Date.now(),
          blocked: false,
          details: {
            function: event.data.function,
            args: event.data.args,
            stack: event.data.stack
          }
        }
        this.reportThreat(threat)
      }
    })
  }
  
  // 报告威胁
  private reportThreat(threat: ThreatDetection) {
    if (this.threatCallback) {
      this.threatCallback(threat)
    }
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'THREAT_DETECTED',
        threat
      }).catch((err: unknown) => console.error('Failed to report threat:', err))
    }
  }

  async scanScripts(): Promise<ThreatDetection[]> {
    const threats: ThreatDetection[] = []
    
    // 扫描内联脚本
    const inlineScripts = document.querySelectorAll('script:not([src])')
    inlineScripts.forEach((script, index) => {
      const scriptThreats = this.analyzeInlineScript(script as HTMLScriptElement, index)
      threats.push(...scriptThreats)
    })
    
    // 扫描外部脚本
    const externalScripts = document.querySelectorAll('script[src]')
    externalScripts.forEach((script, index) => {
      const scriptThreats = this.analyzeExternalScript(script as HTMLScriptElement, index)
      threats.push(...scriptThreats)
    })
    
    return threats
  }

  private analyzeInlineScript(script: HTMLScriptElement, index: number): ThreatDetection[] {
    const threats: ThreatDetection[] = []
    const content = script.textContent || script.innerHTML || ''
    
    if (!content.trim()) return threats
    
    // 如果是本地开发环境，跳过对已存在脚本的静态扫描
    // 只监控动态注入的脚本和实际函数调用
    const isLocalDev = window.location.hostname === 'localhost' || 
                       window.location.hostname === '127.0.0.1' ||
                       window.location.hostname.startsWith('192.168.')
    
    if (isLocalDev && script.hasAttribute('type') && script.getAttribute('type') === 'module') {
      // 跳过Vue/React等框架的模块脚本
      return threats
    }
    
    // 检查可疑模式（仅对非本地开发环境或明确可疑的脚本）
    if (!isLocalDev) {
    this.suspiciousPatterns.forEach((pattern, patternIndex) => {
      const matches = content.match(pattern)
      if (matches) {
        threats.push({
          id: `suspicious_inline_script_${Date.now()}_${index}_${patternIndex}`,
            type: ThreatType.SUSPICIOUS_SCRIPT,
          level: this.getPatternSeverity(pattern),
          url: window.location.href,
          description: `内联脚本包含可疑代码: ${this.getPatternDescription(pattern)}`,
          timestamp: Date.now(),
          blocked: false,
          details: {
            pattern: pattern.toString(),
            matches: matches.slice(0, 3), // 只保留前3个匹配
            scriptContent: content.substring(0, 200) // 只保留前200个字符
          }
        })
      }
    })
    }
    
    // 检查脚本长度（可能是混淆代码）
    if (content.length > 10000 && this.isObfuscated(content)) {
      threats.push({
        id: `obfuscated_script_${Date.now()}_${index}`,
        type: ThreatType.SUSPICIOUS_SCRIPT,
        level: ThreatLevel.MEDIUM,
        url: window.location.href,
        description: '检测到可能的混淆脚本代码',
        timestamp: Date.now(),
        blocked: false,
        details: {
          scriptLength: content.length,
          scriptPreview: content.substring(0, 100)
        }
      })
    }
    
    return threats
  }

  private analyzeExternalScript(script: HTMLScriptElement, index: number): ThreatDetection[] {
    const threats: ThreatDetection[] = []
    const src = script.src
    
    if (!src) return threats
    
    try {
      const url = new URL(src)
      
      // 检查是否为可信域名
      if (!this.isTrustedDomain(url.hostname)) {
        threats.push({
          id: `untrusted_external_script_${Date.now()}_${index}`,
          type: ThreatType.SUSPICIOUS_SCRIPT,
          level: ThreatLevel.MEDIUM,
          url: window.location.href,
          description: `加载来自不可信域名的脚本: ${url.hostname}`,
          timestamp: Date.now(),
          blocked: false,
          details: {
            src,
            domain: url.hostname
          }
        })
      }
      
      // 检查是否使用HTTPS
      if (url.protocol === 'http:' && window.location.protocol === 'https:') {
        threats.push({
          id: `mixed_content_script_${Date.now()}_${index}`,
          type: ThreatType.INSECURE_FORM,
          level: ThreatLevel.MEDIUM,
          url: window.location.href,
          description: 'HTTPS页面加载HTTP脚本（混合内容）',
          timestamp: Date.now(),
          blocked: false,
          details: { src }
        })
      }
      
    } catch (error) {
      // 无效的URL
      threats.push({
        id: `invalid_script_src_${Date.now()}_${index}`,
        type: ThreatType.SUSPICIOUS_SCRIPT,
        level: ThreatLevel.HIGH,
        url: window.location.href,
        description: '脚本src包含无效URL',
        timestamp: Date.now(),
        blocked: false,
        details: { src }
      })
    }
    
    return threats
  }

  private getPatternSeverity(pattern: RegExp): ThreatLevel {
    const patternString = pattern.toString()
    
    if (patternString.includes('eval')) return ThreatLevel.HIGH
    if (patternString.includes('document.write')) return ThreatLevel.MEDIUM
    if (patternString.includes('innerHTML.*<script')) return ThreatLevel.HIGH
    if (patternString.includes('location.href')) return ThreatLevel.MEDIUM
    if (patternString.includes('document.cookie')) return ThreatLevel.MEDIUM
    
    return ThreatLevel.LOW
  }

  private getPatternDescription(pattern: RegExp): string {
    const patternString = pattern.toString()
    
    if (patternString.includes('eval')) return 'eval()函数调用'
    if (patternString.includes('document.write')) return 'document.write()调用'
    if (patternString.includes('innerHTML.*<script')) return 'innerHTML注入脚本'
    if (patternString.includes('location.href')) return '页面重定向'
    if (patternString.includes('document.cookie')) return 'Cookie访问'
    if (patternString.includes('localStorage')) return 'localStorage访问'
    if (patternString.includes('sessionStorage')) return 'sessionStorage访问'
    
    return '可疑代码模式'
  }

  private isObfuscated(content: string): boolean {
    // 简单的混淆检测
    const indicators = [
      /[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*['"]\w+['"]/.test(content), // 大量字符串赋值
      content.split('\n').length < 10 && content.length > 5000, // 代码压缩在少数行
      /\\x[0-9a-fA-F]{2}/.test(content), // 十六进制编码
      /\\u[0-9a-fA-F]{4}/.test(content), // Unicode编码
      (content.match(/[{}]/g) || []).length > content.length * 0.1 // 大量花括号
    ]
    
    return indicators.filter(Boolean).length >= 2
  }

  private isTrustedDomain(hostname: string): boolean {
    const trustedDomains = [
      window.location.hostname,
      // 常见 CDN
      'cdnjs.cloudflare.com',
      'ajax.googleapis.com',
      'code.jquery.com',
      'unpkg.com',
      'jsdelivr.net',
      'stackpath.bootstrapcdn.com',
      'maxcdn.bootstrapcdn.com',
      'fonts.googleapis.com',
      'use.fontawesome.com',
      'cdn.jsdelivr.net',
      'unpkg.com',
      // 大型网站的资源域名
      'twimg.com',           // Twitter/X
      'abs.twimg.com',       // Twitter/X
      'pbs.twimg.com',       // Twitter/X
      'ton.twimg.com',       // Twitter/X
      'facebook.net',        // Facebook
      'fbcdn.net',           // Facebook
      'youtube.com',         // YouTube
      'ytimg.com',           // YouTube
      'googlevideo.com',     // Google
      'gstatic.com',         // Google
      'ggpht.com',           // Google
      'googleusercontent.com', // Google
      'recaptcha.net',       // Google reCAPTCHA
      'cloudflare.com',      // Cloudflare
      'cloudflareinsights.com', // Cloudflare
      'akamaized.net',       // Akamai CDN
      'fastly.net',          // Fastly CDN
      'amazonaws.com',       // AWS
      's3.amazonaws.com',    // AWS S3
      'cloudfront.net'       // AWS CloudFront
    ]
    
    return trustedDomains.some(trusted => 
      hostname === trusted || hostname.endsWith('.' + trusted)
    )
  }
}
