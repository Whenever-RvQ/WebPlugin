import{d as h,T as a,i as L,a as $,b as c,c as A,e as R,g as E,f as z}from"./security-6RDsp77e.js";class U{observer=null;threatCallback;initialize(){this.setupDOMObserver(),console.log("👁️ DOM Observer initialized")}setThreatCallback(e){this.threatCallback=e}setupDOMObserver(){this.observer=new MutationObserver(e=>{e.forEach(t=>{this.handleMutation(t)})}),this.observer.observe(document.body,{childList:!0,subtree:!0,attributes:!0,attributeFilter:["src","href","onclick","onload","onerror"],characterData:!0})}handleMutation(e){switch(e.type){case"childList":this.handleChildListMutation(e);break;case"attributes":this.handleAttributeMutation(e);break;case"characterData":this.handleCharacterDataMutation(e);break}}handleChildListMutation(e){e.addedNodes.forEach(t=>{t.nodeType===Node.ELEMENT_NODE&&this.analyzeAddedElement(t)})}handleAttributeMutation(e){const t=e.target,n=e.attributeName;if(!n)return;const o=t.getAttribute(n);o&&this.isDangerousAttribute(n,o)&&this.reportThreat({id:`dangerous_attribute_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"xss_attack",level:"medium",url:window.location.href,description:`检测到危险属性: ${n}="${o.substring(0,50)}"`,timestamp:Date.now(),blocked:!1,details:{element:t.tagName,attribute:n,value:o.substring(0,200)}})}handleCharacterDataMutation(e){const n=e.target.textContent||"",o=h(n);o.detected&&this.reportThreat({id:`text_xss_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"xss_attack",level:"medium",url:window.location.href,description:"检测到文本内容中的XSS模式",timestamp:Date.now(),blocked:!1,details:{content:n.substring(0,200),patterns:o.patterns.map(s=>s.id)}})}analyzeAddedElement(e){e.tagName==="SCRIPT"&&this.analyzeScriptElement(e),e.tagName==="IFRAME"&&this.analyzeIframeElement(e),e.tagName==="FORM"&&this.analyzeFormElement(e);const t=e.innerHTML;if(t){const n=h(t);n.detected&&this.reportThreat({id:`dynamic_xss_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"xss_attack",level:"high",url:window.location.href,description:"检测到动态添加的XSS内容",timestamp:Date.now(),blocked:!1,details:{element:e.tagName,content:t.substring(0,200),patterns:n.patterns.map(o=>o.id)}})}e.querySelectorAll("*").forEach(n=>{this.analyzeAddedElement(n)})}analyzeScriptElement(e){const t=e.src,n=e.textContent||e.innerHTML;t?this.isTrustedDomain(t)||this.reportThreat({id:`dynamic_external_script_${Date.now()}`,type:"suspicious_script",level:"high",url:window.location.href,description:`动态加载外部脚本: ${new URL(t).hostname}`,timestamp:Date.now(),blocked:!1,details:{src:t}}):n&&this.reportThreat({id:`dynamic_inline_script_${Date.now()}`,type:"suspicious_script",level:"high",url:window.location.href,description:"动态添加内联脚本",timestamp:Date.now(),blocked:!1,details:{content:n.substring(0,200)}})}analyzeIframeElement(e){const t=e.src;t&&!this.isTrustedDomain(t)&&this.reportThreat({id:`dynamic_iframe_${Date.now()}`,type:"suspicious_script",level:"medium",url:window.location.href,description:`动态添加外部iframe: ${new URL(t).hostname}`,timestamp:Date.now(),blocked:!1,details:{src:t}})}analyzeFormElement(e){const t=e.action;if(t&&t!==window.location.href)try{const n=new URL(t),o=new URL(window.location.href);n.hostname!==o.hostname&&this.reportThreat({id:`dynamic_cross_domain_form_${Date.now()}`,type:"suspicious_script",level:"medium",url:window.location.href,description:`动态添加跨域表单: ${n.hostname}`,timestamp:Date.now(),blocked:!1,details:{action:t}})}catch{}}isDangerousAttribute(e,t){return e.startsWith("on")||(e==="src"||e==="href")&&t.startsWith("javascript:")?!0:h(t).detected}isTrustedDomain(e){try{const t=new URL(e).hostname;return[window.location.hostname,"cdnjs.cloudflare.com","ajax.googleapis.com","code.jquery.com","cdn.jsdelivr.net","unpkg.com","jsdelivr.net","twimg.com","abs.twimg.com","pbs.twimg.com","ton.twimg.com","facebook.net","fbcdn.net","gstatic.com","googleusercontent.com","cloudflare.com","cloudflareinsights.com","cloudfront.net"].some(o=>t===o||t.endsWith("."+o))}catch{return!1}}reportThreat(e){this.threatCallback&&this.threatCallback(e)}destroy(){this.observer&&(this.observer.disconnect(),this.observer=null)}}class F{formListeners=new Map;threatCallback;initialize(){console.log("📝 Form Monitor initialized"),this.setupFormMonitoring()}setThreatCallback(e){this.threatCallback=e}setupFormMonitoring(){document.addEventListener("submit",t=>{t.target instanceof HTMLFormElement&&this.onFormSubmit(t)},!0),new MutationObserver(t=>{t.forEach(n=>{n.addedNodes.forEach(o=>{o instanceof HTMLFormElement?this.monitorForm(o):o instanceof HTMLElement&&o.querySelectorAll("form").forEach(s=>this.monitorForm(s))})})}).observe(document.body,{childList:!0,subtree:!0})}monitorForm(e){if(this.formListeners.has(e))return;const t=n=>{this.onFormSubmit(n)};e.addEventListener("submit",t,!0),this.formListeners.set(e,t)}onFormSubmit(e){const t=e.target,n=this.analyzeFormSubmit(t);if(n.length===0)return;n.some(s=>s.level===a.CRITICAL||s.level===a.HIGH)&&(e.preventDefault(),this.showWarning(n),this.reportThreats(n))}showWarning(e){const t=e.map(n=>`• ${n.description}`).join(`
`);console.warn(`⚠️ 检测到安全威胁：

${t}

为了您的安全，表单提交已被阻止。`)}reportThreats(e){typeof chrome<"u"&&chrome.runtime&&chrome.runtime.sendMessage({type:"THREAT_DETECTED",threats:e}).catch(t=>console.error("Failed to report threats:",t)),this.emitThreats(e)}emitThreats(e){this.threatCallback&&e.forEach(t=>this.threatCallback?.(t))}async scanForms(){const e=[];return document.querySelectorAll("form").forEach((n,o)=>{const s=this.analyzeForm(n,o);e.push(...s)}),e}async checkFormSecurity(e){return L(e)}analyzeFormSubmit(e){const t=[],n=new FormData(e);for(const[o,s]of n.entries()){if(typeof s!="string")continue;const r=$(s);r.detected&&r.patterns.forEach(d=>{t.push({id:`sql_injection_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.SQL_INJECTION,level:d.severity,url:window.location.href,description:`表单字段 "${o}" 包含SQL注入攻击: ${d.description}`,timestamp:Date.now(),blocked:!0,details:{field:o,value:s.substring(0,100),pattern:d.id}})});const l=h(s);l.detected&&l.patterns.forEach(d=>{t.push({id:`xss_form_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.XSS_ATTACK,level:d.severity,url:window.location.href,description:`表单字段 "${o}" 包含XSS攻击: ${d.description}`,timestamp:Date.now(),blocked:!0,details:{field:o,value:s.substring(0,100),pattern:d.id}})});const m=A(s);m.detected&&!e.action.startsWith("https://")&&t.push({id:`sensitive_data_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.INSECURE_FORM,level:a.HIGH,url:window.location.href,description:`表单在非HTTPS连接下传输敏感信息: ${m.types.join(", ")}`,timestamp:Date.now(),blocked:!0,details:{field:o,types:m.types}})}return t}analyzeForm(e,t){const n=[],o=e.action||window.location.href,s=e.method.toLowerCase();if(s==="post"&&!o.startsWith("https://")){const r=e.querySelector('input[type="password"]'),l=this.hasSensitiveFields(e);(r||l)&&n.push({id:`insecure_form_${Date.now()}_${t}`,type:c.INSECURE_FORM,level:a.HIGH,url:window.location.href,description:"表单包含敏感信息但未使用HTTPS提交",timestamp:Date.now(),blocked:!1,details:{action:o,method:s,hasPassword:!!r,hasSensitiveFields:l}})}if(o&&o!==window.location.href)try{const r=new URL(o),l=new URL(window.location.href);r.hostname!==l.hostname&&n.push({id:`cross_domain_form_${Date.now()}_${t}`,type:c.SUSPICIOUS_SCRIPT,level:a.MEDIUM,url:window.location.href,description:`表单提交到外部域名: ${r.hostname}`,timestamp:Date.now(),blocked:!1,details:{action:o,targetDomain:r.hostname}})}catch{n.push({id:`invalid_form_action_${Date.now()}_${t}`,type:c.SUSPICIOUS_SCRIPT,level:a.MEDIUM,url:window.location.href,description:"表单action包含无效URL",timestamp:Date.now(),blocked:!1,details:{action:o}})}return n}hasSensitiveFields(e){const t=e.querySelectorAll("input, textarea"),n=[/password/i,/credit.*card/i,/social.*security/i,/ssn/i,/银行卡/i,/密码/i,/身份证/i,/phone/i,/email/i,/address/i];for(const o of t){const s=o,r=`${s.name} ${s.placeholder} ${s.id}`.toLowerCase();if(n.some(l=>l.test(r))||s instanceof HTMLInputElement&&["password","email","tel"].includes(s.type))return!0}return!1}}class H{suspiciousPatterns=[/eval\s*\(/gi,/document\.write\s*\(/gi,/innerHTML\s*=.*<script/gi,/location\.href\s*=/gi,/window\.open\s*\(/gi,/document\.cookie/gi,/localStorage\./gi,/sessionStorage\./gi];threatCallback;initialize(){console.log("📜 Script Monitor initialized"),this.setupRealTimeMonitoring(),this.interceptDangerousFunctions()}setThreatCallback(e){this.threatCallback=e}setupRealTimeMonitoring(){new MutationObserver(t=>{t.forEach(n=>{n.addedNodes.forEach(o=>{o.nodeName==="SCRIPT"&&this.handleDynamicScript(o)})})}).observe(document.documentElement,{childList:!0,subtree:!0})}handleDynamicScript(e){e.src?this.analyzeExternalScript(e,0).forEach(t=>{this.reportThreat(t)}):e.textContent&&this.analyzeInlineScript(e,0).forEach(t=>{this.reportThreat(t)})}interceptDangerousFunctions(){try{const e=document.createElement("script");e.textContent=`
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
    `,(document.head||document.documentElement).insertBefore(e,(document.head||document.documentElement).firstChild),e.remove()}catch{}window.addEventListener("message",e=>{if(e.source===window&&e.data.type==="WEB_SEC_GUARDIAN_ALERT"){const t={id:`dangerous_function_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.XSS_ATTACK,level:a.HIGH,url:window.location.href,description:`检测到危险函数调用: ${e.data.function}()`,timestamp:Date.now(),blocked:!1,details:{function:e.data.function,args:e.data.args,stack:e.data.stack}};this.reportThreat(t)}})}reportThreat(e){this.threatCallback&&this.threatCallback(e),typeof chrome<"u"&&chrome.runtime&&chrome.runtime.sendMessage({type:"THREAT_DETECTED",threat:e}).catch(t=>console.error("Failed to report threat:",t))}async scanScripts(){const e=[];return document.querySelectorAll("script:not([src])").forEach((o,s)=>{const r=this.analyzeInlineScript(o,s);e.push(...r)}),document.querySelectorAll("script[src]").forEach((o,s)=>{const r=this.analyzeExternalScript(o,s);e.push(...r)}),e}analyzeInlineScript(e,t){const n=[],o=e.textContent||e.innerHTML||"";if(!o.trim())return n;const s=window.location.hostname==="localhost"||window.location.hostname==="127.0.0.1"||window.location.hostname.startsWith("192.168.");return s&&e.hasAttribute("type")&&e.getAttribute("type")==="module"||(s||this.suspiciousPatterns.forEach((r,l)=>{const m=o.match(r);m&&n.push({id:`suspicious_inline_script_${Date.now()}_${t}_${l}`,type:c.SUSPICIOUS_SCRIPT,level:this.getPatternSeverity(r),url:window.location.href,description:`内联脚本包含可疑代码: ${this.getPatternDescription(r)}`,timestamp:Date.now(),blocked:!1,details:{pattern:r.toString(),matches:m.slice(0,3),scriptContent:o.substring(0,200)}})}),o.length>1e4&&this.isObfuscated(o)&&n.push({id:`obfuscated_script_${Date.now()}_${t}`,type:c.SUSPICIOUS_SCRIPT,level:a.MEDIUM,url:window.location.href,description:"检测到可能的混淆脚本代码",timestamp:Date.now(),blocked:!1,details:{scriptLength:o.length,scriptPreview:o.substring(0,100)}})),n}analyzeExternalScript(e,t){const n=[],o=e.src;if(!o)return n;try{const s=new URL(o);this.isTrustedDomain(s.hostname)||n.push({id:`untrusted_external_script_${Date.now()}_${t}`,type:c.SUSPICIOUS_SCRIPT,level:a.MEDIUM,url:window.location.href,description:`加载来自不可信域名的脚本: ${s.hostname}`,timestamp:Date.now(),blocked:!1,details:{src:o,domain:s.hostname}}),s.protocol==="http:"&&window.location.protocol==="https:"&&n.push({id:`mixed_content_script_${Date.now()}_${t}`,type:c.INSECURE_FORM,level:a.MEDIUM,url:window.location.href,description:"HTTPS页面加载HTTP脚本（混合内容）",timestamp:Date.now(),blocked:!1,details:{src:o}})}catch{n.push({id:`invalid_script_src_${Date.now()}_${t}`,type:c.SUSPICIOUS_SCRIPT,level:a.HIGH,url:window.location.href,description:"脚本src包含无效URL",timestamp:Date.now(),blocked:!1,details:{src:o}})}return n}getPatternSeverity(e){const t=e.toString();return t.includes("eval")?a.HIGH:t.includes("document.write")?a.MEDIUM:t.includes("innerHTML.*<script")?a.HIGH:t.includes("location.href")?a.MEDIUM:t.includes("document.cookie")?a.MEDIUM:a.LOW}getPatternDescription(e){const t=e.toString();return t.includes("eval")?"eval()函数调用":t.includes("document.write")?"document.write()调用":t.includes("innerHTML.*<script")?"innerHTML注入脚本":t.includes("location.href")?"页面重定向":t.includes("document.cookie")?"Cookie访问":t.includes("localStorage")?"localStorage访问":t.includes("sessionStorage")?"sessionStorage访问":"可疑代码模式"}isObfuscated(e){return[/[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*['"]\w+['"]/.test(e),e.split(`
`).length<10&&e.length>5e3,/\\x[0-9a-fA-F]{2}/.test(e),/\\u[0-9a-fA-F]{4}/.test(e),(e.match(/[{}]/g)||[]).length>e.length*.1].filter(Boolean).length>=2}isTrustedDomain(e){return[window.location.hostname,"cdnjs.cloudflare.com","ajax.googleapis.com","code.jquery.com","unpkg.com","jsdelivr.net","stackpath.bootstrapcdn.com","maxcdn.bootstrapcdn.com","fonts.googleapis.com","use.fontawesome.com","cdn.jsdelivr.net","unpkg.com","twimg.com","abs.twimg.com","pbs.twimg.com","ton.twimg.com","facebook.net","fbcdn.net","youtube.com","ytimg.com","googlevideo.com","gstatic.com","ggpht.com","googleusercontent.com","recaptcha.net","cloudflare.com","cloudflareinsights.com","akamaized.net","fastly.net","amazonaws.com","s3.amazonaws.com","cloudfront.net"].some(n=>e===n||e.endsWith("."+n))}}class P{threats=[];initialize(){console.log("📊 Page Analyzer initialized")}async scanPage(){return this.threats=[],await this.scanContent(),await this.scanExternalResources(),await this.scanUrl(),this.threats}async analyzePage(){const e=await this.scanPage(),t=R(e);return{url:window.location.href,score:t,threats:e,recommendations:this.generateRecommendations(e),scanTime:Date.now(),isSecure:e.length===0}}async scanContent(){const e=document.documentElement.innerHTML,t=h(e);t.detected&&t.patterns.forEach(n=>{this.threats.push({id:`xss_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"xss_attack",level:n.severity,url:window.location.href,description:`检测到XSS模式: ${n.description}`,timestamp:Date.now(),blocked:!1,details:{pattern:n.id}})})}async scanExternalResources(){document.querySelectorAll("script[src]").forEach(n=>{const o=n.src;o&&!this.isTrustedDomain(o)&&this.threats.push({id:`external_script_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"suspicious_script",level:"medium",url:window.location.href,description:`检测到外部脚本: ${new URL(o).hostname}`,timestamp:Date.now(),blocked:!1,details:{src:o}})}),document.querySelectorAll("iframe[src]").forEach(n=>{const o=n.src;o&&!this.isTrustedDomain(o)&&this.threats.push({id:`external_iframe_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"suspicious_script",level:"medium",url:window.location.href,description:`检测到外部iframe: ${new URL(o).hostname}`,timestamp:Date.now(),blocked:!1,details:{src:o}})})}async scanUrl(){const e=window.location.href;!e.startsWith("https://")&&!e.startsWith("file://")&&this.threats.push({id:`insecure_protocol_${Date.now()}`,type:"insecure_form",level:"medium",url:e,description:"网站未使用HTTPS加密连接",timestamp:Date.now(),blocked:!1})}isTrustedDomain(e){try{const t=new URL(e).hostname;return[window.location.hostname,"cdnjs.cloudflare.com","ajax.googleapis.com","code.jquery.com","unpkg.com","jsdelivr.net","cdn.jsdelivr.net","twimg.com","abs.twimg.com","pbs.twimg.com","ton.twimg.com","facebook.net","fbcdn.net","gstatic.com","googleusercontent.com","cloudflare.com","cloudflareinsights.com","cloudfront.net"].some(o=>t===o||t.endsWith("."+o))}catch{return!1}}generateRecommendations(e){const t=[],n=new Set(e.map(o=>o.type));return n.has("xss_attack")&&t.push("检测到XSS风险，建议更新浏览器并启用安全防护"),n.has("suspicious_script")&&t.push("发现可疑外部资源，请确认网站可信度"),n.has("insecure_form")&&t.push("网站未使用HTTPS，避免输入敏感信息"),t.length===0&&t.push("页面安全检查通过，但仍需保持警惕"),t}}console.log("🛡️ Web Security Guardian 内容脚本启动:",window.location.href);const x=new U,S=new F,v=new H,O=new P,T=new Set,g=[];let w=!1,b=null,u=!1,f=!1,_=!1;async function N(){try{const i=window.location.hostname,e=await chrome.storage.local.get(["whitelist"]);let t=[];return e.whitelist&&Array.isArray(e.whitelist)&&(t=e.whitelist),console.log("🔍 白名单检查:",{当前域名:i,白名单数量:t.length}),t.length===0?(u=!1,!1):(u=t.some(n=>i===n||i.endsWith(`.${n}`)),u&&(console.log("✅ 当前网站在白名单中，已禁用所有安全检测"),W()),u)}catch(i){return console.error("❌ 检查白名单失败:",i),u=!1,!1}}function W(){if(!document.body)return;const i=document.createElement("div");i.style.cssText="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:linear-gradient(135deg,#667eea,#764ba2);color:white;padding:32px 40px;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.3);z-index:2147483647;text-align:center;min-width:400px",i.innerHTML='<div style="font-size:48px;margin-bottom:16px">✅</div><h2 style="margin:0 0 12px;font-size:24px;font-weight:700">白名单网站</h2><p style="margin:0 0 24px;font-size:14px;opacity:0.8">当前网站已加入白名单<br>所有安全检测功能已禁用</p><button onclick="this.parentElement.remove()" style="background:rgba(255,255,255,0.2);border:2px solid rgba(255,255,255,0.4);color:white;padding:12px 32px;border-radius:8px;font-size:14px;cursor:pointer">我知道了</button>';const e=document.createElement("div");e.style.cssText="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:2147483646",e.onclick=()=>{i.remove(),e.remove()},document.body.appendChild(e),document.body.appendChild(i),setTimeout(()=>{i.parentElement&&(i.remove(),e.remove())},3e3)}async function B(){try{const i=window.location.hostname,e=await chrome.storage.local.get(["blacklist"]);let t=[];return e.blacklist&&Array.isArray(e.blacklist)&&(t=e.blacklist),console.log("🔍 黑名单检查:",{当前域名:i,黑名单数量:t.length}),t.length===0?(f=!1,!1):(f=t.some(n=>i===n||i.endsWith(`.${n}`)),f?(console.log("⚠️ 当前网站在黑名单中，显示警告弹窗"),!0):!1)}catch(i){return console.error("❌ 检查黑名单失败:",i),f=!1,!1}}function j(){return new Promise(i=>{if(!document.body){i(!1);return}const e=document.createElement("div");e.style.cssText="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);z-index:2147483646;backdrop-filter:blur(10px)";const t=document.createElement("div");t.style.cssText="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:linear-gradient(135deg,#ff416c,#ff4b2b);color:white;padding:48px;border-radius:24px;box-shadow:0 30px 90px rgba(255,65,108,0.5);z-index:2147483647;text-align:center;min-width:500px;animation:warningPulse 2s ease-in-out infinite";const n=document.createElement("style");n.textContent=`
      @keyframes warningPulse {
        0%, 100% { box-shadow: 0 30px 90px rgba(255,65,108,0.5); }
        50% { box-shadow: 0 30px 90px rgba(255,65,108,0.8), 0 0 40px rgba(255,65,108,0.6); }
      }
    `,document.head.appendChild(n),t.innerHTML=`
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
    `;const o=document.createElement("style");o.textContent=`
      @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-5px) rotate(-5deg); }
        75% { transform: translateX(5px) rotate(5deg); }
      }
    `,document.head.appendChild(o),document.body.appendChild(e),document.body.appendChild(t);const s=document.getElementById("blacklistExit");s&&(s.onmouseover=()=>{s.style.transform="scale(1.05)",s.style.boxShadow="0 6px 20px rgba(0,0,0,0.3)"},s.onmouseout=()=>{s.style.transform="scale(1)",s.style.boxShadow="0 4px 12px rgba(0,0,0,0.2)"},s.onclick=()=>{console.log("🚪 用户选择退出黑名单网站"),t.remove(),e.remove(),n.remove(),o.remove(),window.location.href="about:blank",i(!1)});const r=document.getElementById("blacklistContinue");r&&(r.onmouseover=()=>{r.style.background="rgba(255,255,255,0.25)",r.style.transform="scale(1.05)"},r.onmouseout=()=>{r.style.background="rgba(255,255,255,0.15)",r.style.transform="scale(1)"},r.onclick=()=>{console.log("⚡ 用户选择继续进入黑名单网站"),t.remove(),e.remove(),n.remove(),o.remove(),_=!0,i(!0)})})}function D(){return typeof chrome<"u"&&!!chrome.runtime?.sendMessage}function G(i){D()&&(T.has(i.id)||(T.add(i.id),chrome.runtime.sendMessage({type:"THREAT_DETECTED",threat:i}).catch(e=>console.error("Failed to notify background:",e))))}function C(i){switch(i){case c.MALICIOUS_URL:return"恶意网址";case c.XSS_ATTACK:return"XSS攻击";case c.SQL_INJECTION:return"SQL注入";case c.TRACKER:return"追踪器";case c.INSECURE_FORM:return"不安全传输";case c.SUSPICIOUS_SCRIPT:return"可疑脚本";case c.PHISHING:return"钓鱼风险";case c.DATA_LEAK:return"敏感信息泄露";default:return"安全警告"}}function q(i){switch(i){case a.CRITICAL:return"linear-gradient(135deg, #ff1744, #b71c1c)";case a.HIGH:return"linear-gradient(135deg, #ff6b6b, #d32f2f)";case a.MEDIUM:return"linear-gradient(135deg, #ffb74d, #f57c00)";case a.LOW:return"linear-gradient(135deg, #66bb6a, #2e7d32)";default:return"linear-gradient(135deg, #607d8b, #455a64)"}}function I(i){if(!document.body){g.push(i);return}let e=i.url;try{e=new URL(i.url).hostname}catch{}const t="wsg-threat-container";let n=document.getElementById(t);n||(n=document.createElement("div"),n.id=t,n.style.cssText=`
    position: fixed;
    top: 20px;
    right: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
      z-index: 2147483647;
      max-width: 380px;
      pointer-events: none;
    `,document.body.appendChild(n));const o=document.createElement("div");o.style.cssText=`
    display: flex;
    align-items: flex-start;
    gap: 14px;
    padding: 18px 20px;
    border-radius: 16px;
    color: #fff;
    box-shadow: 0 8px 32px rgba(0,0,0,0.12), 0 2px 8px rgba(0,0,0,0.08);
    background: ${q(i.level)};
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
  `;const s=document.createElement("div");if(s.style.cssText=`
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
    animation: shine 3s infinite;
  `,o.appendChild(s),o.innerHTML+=`
    <div style="font-size: 24px; line-height: 1; animation: bounce 0.6s ease;">🛡️</div>
    <div style="flex: 1; min-width: 0;">
      <div style="font-weight: 700; font-size: 14px; margin-bottom: 6px; letter-spacing: 0.3px;">
        ${C(i.type)} · ${i.level.toUpperCase()}
      </div>
      <div style="font-size: 13px; word-break: break-word; line-height: 1.6; opacity: 0.95;">${i.description}</div>
      <div style="margin-top: 8px; font-size: 11px; opacity: 0.8; font-weight: 500;">
        📍 ${e}
      </div>
    </div>
    <button type="button" aria-label="关闭警告"
      style="background: rgba(255,255,255,0.2); border: none; color: #fff; font-size: 20px; cursor: pointer; line-height: 1; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; transition: all 0.2s; flex-shrink: 0;">×</button>
  `,!document.getElementById("wsg-toast-animations")){const l=document.createElement("style");l.id="wsg-toast-animations",l.textContent=`
      @keyframes shine {
        0% { left: -100%; }
        50% { left: 100%; }
        100% { left: 100%; }
      }
      @keyframes bounce {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.2); }
      }
    `,document.head.appendChild(l)}const r=o.querySelector("button");r?.addEventListener("mouseenter",()=>{r instanceof HTMLElement&&(r.style.background="rgba(255,255,255,0.3)",r.style.transform="scale(1.1)")}),r?.addEventListener("mouseleave",()=>{r instanceof HTMLElement&&(r.style.background="rgba(255,255,255,0.2)",r.style.transform="scale(1)")}),r?.addEventListener("click",l=>{l.stopPropagation(),o.style.opacity="0",o.style.transform="translateX(400px) scale(0.8)",setTimeout(()=>o.remove(),400)}),n.appendChild(o),requestAnimationFrame(()=>{requestAnimationFrame(()=>{o.style.opacity="1",o.style.transform="translateX(0) scale(1)"})}),setTimeout(()=>{o.style.opacity="0",o.style.transform="translateX(400px) scale(0.8)",setTimeout(()=>o.remove(),400)},6e3)}function X(){if(!g.length)return;const i=[...g];g.length=0,i.forEach(I)}function p(i,e={}){u||(console.warn("🚨 威胁检测:",{类型:C(i.type),等级:i.level.toUpperCase(),描述:i.description,详情:i.details}),I(i),e.notifyBackground&&G(i))}const y=document.createElement("meta");y.name="web-security-guardian";y.content="active";document.head?.appendChild(y);window.webSecurityGuardian={version:"1.0.0",isActive:!0,reportThreat:i=>{const e={id:i.id||E(),type:i.type||c.DATA_LEAK,level:i.level||a.MEDIUM,url:i.url||window.location.href,description:i.description||"检测到未知安全威胁",timestamp:i.timestamp||Date.now(),blocked:i.blocked??!1,details:i.details};p(e,{notifyBackground:!0})}};function M(i,e){try{const t=new URL(i,window.location.href).href,n=z(t);if(n.detected){const o={id:E(),type:c.PHISHING,level:n.score>=80?a.CRITICAL:a.HIGH,url:t,description:`检测到疑似钓鱼链接（来源：${e}）`,timestamp:Date.now(),blocked:!0,details:{reasons:n.reasons,score:n.score,source:e}};return p(o,{notifyBackground:!0}),console.warn("🎣 钓鱼风险详情:",n.reasons),!0}}catch(t){console.warn("无法解析URL进行安全检查:",i,t)}return!1}function K(){document.addEventListener("click",i=>{if(!(i.target instanceof Element))return;const e=i.target.closest("a[href]");if(!e)return;const t=e.href;M(t,"anchor_click")&&(i.preventDefault(),i.stopImmediatePropagation())},!0)}function Q(){const i=window.open;window.open=function(...e){const t=e[0],n=typeof t=="string"?t:t?.toString?.();return typeof n=="string"&&M(n,"window.open")?null:i.apply(window,e)}}async function k(){if(X(),await N()){console.log("⏸️ 白名单网站，已禁用所有安全检测");return}if(await B()&&!_){if(console.log("⚠️ 黑名单网站，显示警告弹窗"),!await j()){console.log("🚫 用户拒绝进入黑名单网站");return}console.log("✅ 用户选择继续进入黑名单网站")}D()&&chrome.runtime.sendMessage({type:"PAGE_NAVIGATION",url:window.location.href}).then(s=>{s?.clearedCount>0&&console.log(`🗑️ 已清除 ${s.clearedCount} 条历史威胁，开始重新评估`)}).catch(s=>console.error("Failed to notify page navigation:",s));let t=!1;function n(){t||(t=!0,x.setThreatCallback(s=>p(s,{notifyBackground:!0})),x.initialize(),S.setThreatCallback(s=>p(s,{notifyBackground:!0})),S.initialize(),v.setThreatCallback(s=>p(s,{notifyBackground:!0})),v.initialize(),console.log("✅ 监控器已启动"))}function o(){u||(w||(w=!0,console.log("👆 检测到用户交互，启动监控"),n()),b&&clearTimeout(b),b=window.setTimeout(()=>{w=!1,console.log("⏸️ 用户交互超时，暂停监控")},5e3))}document.addEventListener("click",o,!0),document.addEventListener("submit",o,!0),document.addEventListener("keydown",s=>{s.key==="Enter"&&o()},!0),O.initialize(),K(),console.log("✅ Web Security Guardian 内容脚本已激活（实时监控模式）")}Q();document.readyState==="loading"?document.addEventListener("DOMContentLoaded",k):k();
