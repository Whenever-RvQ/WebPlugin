import{d as m,T as a,i as C,a as M,b as c,c as L,e as $,g as _,f as R}from"./security-6RDsp77e.js";class A{observer=null;threatCallback;initialize(){this.setupDOMObserver(),console.log("👁️ DOM Observer initialized")}setThreatCallback(t){this.threatCallback=t}setupDOMObserver(){this.observer=new MutationObserver(t=>{t.forEach(e=>{this.handleMutation(e)})}),this.observer.observe(document.body,{childList:!0,subtree:!0,attributes:!0,attributeFilter:["src","href","onclick","onload","onerror"],characterData:!0})}handleMutation(t){switch(t.type){case"childList":this.handleChildListMutation(t);break;case"attributes":this.handleAttributeMutation(t);break;case"characterData":this.handleCharacterDataMutation(t);break}}handleChildListMutation(t){t.addedNodes.forEach(e=>{e.nodeType===Node.ELEMENT_NODE&&this.analyzeAddedElement(e)})}handleAttributeMutation(t){const e=t.target,i=t.attributeName;if(!i)return;const n=e.getAttribute(i);n&&this.isDangerousAttribute(i,n)&&this.reportThreat({id:`dangerous_attribute_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"xss_attack",level:"medium",url:window.location.href,description:`检测到危险属性: ${i}="${n.substring(0,50)}"`,timestamp:Date.now(),blocked:!1,details:{element:e.tagName,attribute:i,value:n.substring(0,200)}})}handleCharacterDataMutation(t){const i=t.target.textContent||"",n=m(i);n.detected&&this.reportThreat({id:`text_xss_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"xss_attack",level:"medium",url:window.location.href,description:"检测到文本内容中的XSS模式",timestamp:Date.now(),blocked:!1,details:{content:i.substring(0,200),patterns:n.patterns.map(s=>s.id)}})}analyzeAddedElement(t){t.tagName==="SCRIPT"&&this.analyzeScriptElement(t),t.tagName==="IFRAME"&&this.analyzeIframeElement(t),t.tagName==="FORM"&&this.analyzeFormElement(t);const e=t.innerHTML;if(e){const i=m(e);i.detected&&this.reportThreat({id:`dynamic_xss_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"xss_attack",level:"high",url:window.location.href,description:"检测到动态添加的XSS内容",timestamp:Date.now(),blocked:!1,details:{element:t.tagName,content:e.substring(0,200),patterns:i.patterns.map(n=>n.id)}})}t.querySelectorAll("*").forEach(i=>{this.analyzeAddedElement(i)})}analyzeScriptElement(t){const e=t.src,i=t.textContent||t.innerHTML;e?this.isTrustedDomain(e)||this.reportThreat({id:`dynamic_external_script_${Date.now()}`,type:"suspicious_script",level:"high",url:window.location.href,description:`动态加载外部脚本: ${new URL(e).hostname}`,timestamp:Date.now(),blocked:!1,details:{src:e}}):i&&this.reportThreat({id:`dynamic_inline_script_${Date.now()}`,type:"suspicious_script",level:"high",url:window.location.href,description:"动态添加内联脚本",timestamp:Date.now(),blocked:!1,details:{content:i.substring(0,200)}})}analyzeIframeElement(t){const e=t.src;e&&!this.isTrustedDomain(e)&&this.reportThreat({id:`dynamic_iframe_${Date.now()}`,type:"suspicious_script",level:"medium",url:window.location.href,description:`动态添加外部iframe: ${new URL(e).hostname}`,timestamp:Date.now(),blocked:!1,details:{src:e}})}analyzeFormElement(t){const e=t.action;if(e&&e!==window.location.href)try{const i=new URL(e),n=new URL(window.location.href);i.hostname!==n.hostname&&this.reportThreat({id:`dynamic_cross_domain_form_${Date.now()}`,type:"suspicious_script",level:"medium",url:window.location.href,description:`动态添加跨域表单: ${i.hostname}`,timestamp:Date.now(),blocked:!1,details:{action:e}})}catch{}}isDangerousAttribute(t,e){return t.startsWith("on")||(t==="src"||t==="href")&&e.startsWith("javascript:")?!0:m(e).detected}isTrustedDomain(t){try{const e=new URL(t).hostname;return[window.location.hostname,"cdnjs.cloudflare.com","ajax.googleapis.com","code.jquery.com","cdn.jsdelivr.net","unpkg.com","jsdelivr.net","twimg.com","abs.twimg.com","pbs.twimg.com","ton.twimg.com","facebook.net","fbcdn.net","gstatic.com","googleusercontent.com","cloudflare.com","cloudflareinsights.com","cloudfront.net"].some(n=>e===n||e.endsWith("."+n))}catch{return!1}}reportThreat(t){this.threatCallback&&this.threatCallback(t)}destroy(){this.observer&&(this.observer.disconnect(),this.observer=null)}}class U{formListeners=new Map;threatCallback;initialize(){console.log("📝 Form Monitor initialized"),this.setupFormMonitoring()}setThreatCallback(t){this.threatCallback=t}setupFormMonitoring(){document.addEventListener("submit",e=>{e.target instanceof HTMLFormElement&&this.onFormSubmit(e)},!0),new MutationObserver(e=>{e.forEach(i=>{i.addedNodes.forEach(n=>{n instanceof HTMLFormElement?this.monitorForm(n):n instanceof HTMLElement&&n.querySelectorAll("form").forEach(s=>this.monitorForm(s))})})}).observe(document.body,{childList:!0,subtree:!0})}monitorForm(t){if(this.formListeners.has(t))return;const e=i=>{this.onFormSubmit(i)};t.addEventListener("submit",e,!0),this.formListeners.set(t,e)}onFormSubmit(t){const e=t.target,i=this.analyzeFormSubmit(e);if(i.length===0)return;i.some(s=>s.level===a.CRITICAL||s.level===a.HIGH)&&(t.preventDefault(),this.showWarning(i),this.reportThreats(i))}showWarning(t){const e=t.map(i=>`• ${i.description}`).join(`
`);console.warn(`⚠️ 检测到安全威胁：

${e}

为了您的安全，表单提交已被阻止。`)}reportThreats(t){typeof chrome<"u"&&chrome.runtime&&chrome.runtime.sendMessage({type:"THREAT_DETECTED",threats:t}).catch(e=>console.error("Failed to report threats:",e)),this.emitThreats(t)}emitThreats(t){this.threatCallback&&t.forEach(e=>this.threatCallback?.(e))}async scanForms(){const t=[];return document.querySelectorAll("form").forEach((i,n)=>{const s=this.analyzeForm(i,n);t.push(...s)}),t}async checkFormSecurity(t){return C(t)}analyzeFormSubmit(t){const e=[],i=new FormData(t);for(const[n,s]of i.entries()){if(typeof s!="string")continue;const r=M(s);r.detected&&r.patterns.forEach(d=>{e.push({id:`sql_injection_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.SQL_INJECTION,level:d.severity,url:window.location.href,description:`表单字段 "${n}" 包含SQL注入攻击: ${d.description}`,timestamp:Date.now(),blocked:!0,details:{field:n,value:s.substring(0,100),pattern:d.id}})});const l=m(s);l.detected&&l.patterns.forEach(d=>{e.push({id:`xss_form_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.XSS_ATTACK,level:d.severity,url:window.location.href,description:`表单字段 "${n}" 包含XSS攻击: ${d.description}`,timestamp:Date.now(),blocked:!0,details:{field:n,value:s.substring(0,100),pattern:d.id}})});const u=L(s);u.detected&&!t.action.startsWith("https://")&&e.push({id:`sensitive_data_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.INSECURE_FORM,level:a.HIGH,url:window.location.href,description:`表单在非HTTPS连接下传输敏感信息: ${u.types.join(", ")}`,timestamp:Date.now(),blocked:!0,details:{field:n,types:u.types}})}return e}analyzeForm(t,e){const i=[],n=t.action||window.location.href,s=t.method.toLowerCase();if(s==="post"&&!n.startsWith("https://")){const r=t.querySelector('input[type="password"]'),l=this.hasSensitiveFields(t);(r||l)&&i.push({id:`insecure_form_${Date.now()}_${e}`,type:c.INSECURE_FORM,level:a.HIGH,url:window.location.href,description:"表单包含敏感信息但未使用HTTPS提交",timestamp:Date.now(),blocked:!1,details:{action:n,method:s,hasPassword:!!r,hasSensitiveFields:l}})}if(n&&n!==window.location.href)try{const r=new URL(n),l=new URL(window.location.href);r.hostname!==l.hostname&&i.push({id:`cross_domain_form_${Date.now()}_${e}`,type:c.SUSPICIOUS_SCRIPT,level:a.MEDIUM,url:window.location.href,description:`表单提交到外部域名: ${r.hostname}`,timestamp:Date.now(),blocked:!1,details:{action:n,targetDomain:r.hostname}})}catch{i.push({id:`invalid_form_action_${Date.now()}_${e}`,type:c.SUSPICIOUS_SCRIPT,level:a.MEDIUM,url:window.location.href,description:"表单action包含无效URL",timestamp:Date.now(),blocked:!1,details:{action:n}})}return i}hasSensitiveFields(t){const e=t.querySelectorAll("input, textarea"),i=[/password/i,/credit.*card/i,/social.*security/i,/ssn/i,/银行卡/i,/密码/i,/身份证/i,/phone/i,/email/i,/address/i];for(const n of e){const s=n,r=`${s.name} ${s.placeholder} ${s.id}`.toLowerCase();if(i.some(l=>l.test(r))||s instanceof HTMLInputElement&&["password","email","tel"].includes(s.type))return!0}return!1}}class z{suspiciousPatterns=[/eval\s*\(/gi,/document\.write\s*\(/gi,/innerHTML\s*=.*<script/gi,/location\.href\s*=/gi,/window\.open\s*\(/gi,/document\.cookie/gi,/localStorage\./gi,/sessionStorage\./gi];threatCallback;initialize(){console.log("📜 Script Monitor initialized"),this.setupRealTimeMonitoring(),this.interceptDangerousFunctions()}setThreatCallback(t){this.threatCallback=t}setupRealTimeMonitoring(){new MutationObserver(e=>{e.forEach(i=>{i.addedNodes.forEach(n=>{n.nodeName==="SCRIPT"&&this.handleDynamicScript(n)})})}).observe(document.documentElement,{childList:!0,subtree:!0})}handleDynamicScript(t){t.src?this.analyzeExternalScript(t,0).forEach(e=>{this.reportThreat(e)}):t.textContent&&this.analyzeInlineScript(t,0).forEach(e=>{this.reportThreat(e)})}interceptDangerousFunctions(){try{const t=document.createElement("script");t.textContent=`
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
      `,(document.head||document.documentElement).insertBefore(t,(document.head||document.documentElement).firstChild),t.remove()}catch{}window.addEventListener("message",t=>{if(t.source===window&&t.data.type==="WEB_SEC_GUARDIAN_ALERT"){const e={id:`dangerous_function_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.XSS_ATTACK,level:a.HIGH,url:window.location.href,description:`检测到危险函数调用: ${t.data.function}()`,timestamp:Date.now(),blocked:!1,details:{function:t.data.function,args:t.data.args,stack:t.data.stack}};this.reportThreat(e)}})}reportThreat(t){this.threatCallback&&this.threatCallback(t),typeof chrome<"u"&&chrome.runtime&&chrome.runtime.sendMessage({type:"THREAT_DETECTED",threat:t}).catch(e=>console.error("Failed to report threat:",e))}async scanScripts(){const t=[];return document.querySelectorAll("script:not([src])").forEach((n,s)=>{const r=this.analyzeInlineScript(n,s);t.push(...r)}),document.querySelectorAll("script[src]").forEach((n,s)=>{const r=this.analyzeExternalScript(n,s);t.push(...r)}),t}analyzeInlineScript(t,e){const i=[],n=t.textContent||t.innerHTML||"";if(!n.trim())return i;const s=window.location.hostname==="localhost"||window.location.hostname==="127.0.0.1"||window.location.hostname.startsWith("192.168.");return s&&t.hasAttribute("type")&&t.getAttribute("type")==="module"||(s||this.suspiciousPatterns.forEach((r,l)=>{const u=n.match(r);u&&i.push({id:`suspicious_inline_script_${Date.now()}_${e}_${l}`,type:c.SUSPICIOUS_SCRIPT,level:this.getPatternSeverity(r),url:window.location.href,description:`内联脚本包含可疑代码: ${this.getPatternDescription(r)}`,timestamp:Date.now(),blocked:!1,details:{pattern:r.toString(),matches:u.slice(0,3),scriptContent:n.substring(0,200)}})}),n.length>1e4&&this.isObfuscated(n)&&i.push({id:`obfuscated_script_${Date.now()}_${e}`,type:c.SUSPICIOUS_SCRIPT,level:a.MEDIUM,url:window.location.href,description:"检测到可能的混淆脚本代码",timestamp:Date.now(),blocked:!1,details:{scriptLength:n.length,scriptPreview:n.substring(0,100)}})),i}analyzeExternalScript(t,e){const i=[],n=t.src;if(!n)return i;try{const s=new URL(n);this.isTrustedDomain(s.hostname)||i.push({id:`untrusted_external_script_${Date.now()}_${e}`,type:c.SUSPICIOUS_SCRIPT,level:a.MEDIUM,url:window.location.href,description:`加载来自不可信域名的脚本: ${s.hostname}`,timestamp:Date.now(),blocked:!1,details:{src:n,domain:s.hostname}}),s.protocol==="http:"&&window.location.protocol==="https:"&&i.push({id:`mixed_content_script_${Date.now()}_${e}`,type:c.INSECURE_FORM,level:a.MEDIUM,url:window.location.href,description:"HTTPS页面加载HTTP脚本（混合内容）",timestamp:Date.now(),blocked:!1,details:{src:n}})}catch{i.push({id:`invalid_script_src_${Date.now()}_${e}`,type:c.SUSPICIOUS_SCRIPT,level:a.HIGH,url:window.location.href,description:"脚本src包含无效URL",timestamp:Date.now(),blocked:!1,details:{src:n}})}return i}getPatternSeverity(t){const e=t.toString();return e.includes("eval")?a.HIGH:e.includes("document.write")?a.MEDIUM:e.includes("innerHTML.*<script")?a.HIGH:e.includes("location.href")?a.MEDIUM:e.includes("document.cookie")?a.MEDIUM:a.LOW}getPatternDescription(t){const e=t.toString();return e.includes("eval")?"eval()函数调用":e.includes("document.write")?"document.write()调用":e.includes("innerHTML.*<script")?"innerHTML注入脚本":e.includes("location.href")?"页面重定向":e.includes("document.cookie")?"Cookie访问":e.includes("localStorage")?"localStorage访问":e.includes("sessionStorage")?"sessionStorage访问":"可疑代码模式"}isObfuscated(t){return[/[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*['"]\w+['"]/.test(t),t.split(`
`).length<10&&t.length>5e3,/\\x[0-9a-fA-F]{2}/.test(t),/\\u[0-9a-fA-F]{4}/.test(t),(t.match(/[{}]/g)||[]).length>t.length*.1].filter(Boolean).length>=2}isTrustedDomain(t){return[window.location.hostname,"cdnjs.cloudflare.com","ajax.googleapis.com","code.jquery.com","unpkg.com","jsdelivr.net","stackpath.bootstrapcdn.com","maxcdn.bootstrapcdn.com","fonts.googleapis.com","use.fontawesome.com","cdn.jsdelivr.net","unpkg.com","twimg.com","abs.twimg.com","pbs.twimg.com","ton.twimg.com","facebook.net","fbcdn.net","youtube.com","ytimg.com","googlevideo.com","gstatic.com","ggpht.com","googleusercontent.com","recaptcha.net","cloudflare.com","cloudflareinsights.com","akamaized.net","fastly.net","amazonaws.com","s3.amazonaws.com","cloudfront.net"].some(i=>t===i||t.endsWith("."+i))}}class F{threats=[];initialize(){console.log("📊 Page Analyzer initialized")}async scanPage(){return this.threats=[],await this.scanContent(),await this.scanExternalResources(),await this.scanUrl(),this.threats}async analyzePage(){const t=await this.scanPage(),e=$(t);return{url:window.location.href,score:e,threats:t,recommendations:this.generateRecommendations(t),scanTime:Date.now(),isSecure:t.length===0}}async scanContent(){const t=document.documentElement.innerHTML,e=m(t);e.detected&&e.patterns.forEach(i=>{this.threats.push({id:`xss_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"xss_attack",level:i.severity,url:window.location.href,description:`检测到XSS模式: ${i.description}`,timestamp:Date.now(),blocked:!1,details:{pattern:i.id}})})}async scanExternalResources(){document.querySelectorAll("script[src]").forEach(i=>{const n=i.src;n&&!this.isTrustedDomain(n)&&this.threats.push({id:`external_script_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"suspicious_script",level:"medium",url:window.location.href,description:`检测到外部脚本: ${new URL(n).hostname}`,timestamp:Date.now(),blocked:!1,details:{src:n}})}),document.querySelectorAll("iframe[src]").forEach(i=>{const n=i.src;n&&!this.isTrustedDomain(n)&&this.threats.push({id:`external_iframe_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"suspicious_script",level:"medium",url:window.location.href,description:`检测到外部iframe: ${new URL(n).hostname}`,timestamp:Date.now(),blocked:!1,details:{src:n}})})}async scanUrl(){const t=window.location.href;!t.startsWith("https://")&&!t.startsWith("file://")&&this.threats.push({id:`insecure_protocol_${Date.now()}`,type:"insecure_form",level:"medium",url:t,description:"网站未使用HTTPS加密连接",timestamp:Date.now(),blocked:!1})}isTrustedDomain(t){try{const e=new URL(t).hostname;return[window.location.hostname,"cdnjs.cloudflare.com","ajax.googleapis.com","code.jquery.com","unpkg.com","jsdelivr.net","cdn.jsdelivr.net","twimg.com","abs.twimg.com","pbs.twimg.com","ton.twimg.com","facebook.net","fbcdn.net","gstatic.com","googleusercontent.com","cloudflare.com","cloudflareinsights.com","cloudfront.net"].some(n=>e===n||e.endsWith("."+n))}catch{return!1}}generateRecommendations(t){const e=[],i=new Set(t.map(n=>n.type));return i.has("xss_attack")&&e.push("检测到XSS风险，建议更新浏览器并启用安全防护"),i.has("suspicious_script")&&e.push("发现可疑外部资源，请确认网站可信度"),i.has("insecure_form")&&e.push("网站未使用HTTPS，避免输入敏感信息"),e.length===0&&e.push("页面安全检查通过，但仍需保持警惕"),e}}console.log("🛡️ Web Security Guardian 内容脚本启动:",window.location.href);const b=new A,S=new U,T=new z,H=new F,v=new Set,p=[];let g=!1,w=null,f=!1;async function P(){try{const o=window.location.hostname,e=(await chrome.storage.local.get(["whitelist"])).whitelist||[];return console.log("🔍 白名单检查:",{当前域名:o,白名单数量:e.length,白名单内容:e}),f=e.some(i=>{const n=o===i||o.endsWith(`.${i}`);return n&&console.log(`✅ 域名匹配成功: ${o} 匹配 ${i}`),n}),f?(console.log("✅ 当前网站在白名单中，已禁用所有安全检测"),O(),!0):(console.log("ℹ️ 当前网站不在白名单中，正常启用安全检测"),!1)}catch(o){return console.error("❌ 检查白名单失败:",o),!1}}function O(){const o=document.createElement("div");o.id="wsg-whitelist-notification",o.style.cssText=`
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
  `,o.innerHTML=`
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
  `;const t=document.createElement("style");t.textContent=`
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
  `,document.head.appendChild(t);const e=document.createElement("div");e.style.cssText=`
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.5);
    z-index: 2147483646;
    animation: fadeIn 0.3s;
  `;const i=document.createElement("style");i.textContent=`
    @keyframes fadeIn {
      0% { opacity: 0; }
      100% { opacity: 1; }
    }
  `,document.head.appendChild(i),e.onclick=()=>{o.style.opacity="0",o.style.transform="translate(-50%, -50%) scale(0.9)",e.style.opacity="0",setTimeout(()=>{o.remove(),e.remove()},300)},document.body.appendChild(e),document.body.appendChild(o),setTimeout(()=>{o.parentElement&&(o.style.opacity="0",o.style.transform="translate(-50%, -50%) scale(0.9)",e.style.opacity="0",setTimeout(()=>{o.remove(),e.remove()},300))},3e3)}function k(){return typeof chrome<"u"&&!!chrome.runtime?.sendMessage}function N(o){k()&&(v.has(o.id)||(v.add(o.id),chrome.runtime.sendMessage({type:"THREAT_DETECTED",threat:o}).catch(t=>console.error("Failed to notify background:",t))))}function D(o){switch(o){case c.MALICIOUS_URL:return"恶意网址";case c.XSS_ATTACK:return"XSS攻击";case c.SQL_INJECTION:return"SQL注入";case c.TRACKER:return"追踪器";case c.INSECURE_FORM:return"不安全传输";case c.SUSPICIOUS_SCRIPT:return"可疑脚本";case c.PHISHING:return"钓鱼风险";case c.DATA_LEAK:return"敏感信息泄露";default:return"安全警告"}}function W(o){switch(o){case a.CRITICAL:return"linear-gradient(135deg, #ff1744, #b71c1c)";case a.HIGH:return"linear-gradient(135deg, #ff6b6b, #d32f2f)";case a.MEDIUM:return"linear-gradient(135deg, #ffb74d, #f57c00)";case a.LOW:return"linear-gradient(135deg, #66bb6a, #2e7d32)";default:return"linear-gradient(135deg, #607d8b, #455a64)"}}function x(o){if(!document.body){p.push(o);return}let t=o.url;try{t=new URL(o.url).hostname}catch{}const e="wsg-threat-container";let i=document.getElementById(e);i||(i=document.createElement("div"),i.id=e,i.style.cssText=`
      position: fixed;
      top: 20px;
      right: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
      z-index: 2147483647;
      max-width: 380px;
      pointer-events: none;
    `,document.body.appendChild(i));const n=document.createElement("div");n.style.cssText=`
    display: flex;
    align-items: flex-start;
    gap: 14px;
    padding: 18px 20px;
    border-radius: 16px;
    color: #fff;
    box-shadow: 0 8px 32px rgba(0,0,0,0.12), 0 2px 8px rgba(0,0,0,0.08);
    background: ${W(o.level)};
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
  `,n.appendChild(s),n.innerHTML+=`
    <div style="font-size: 24px; line-height: 1; animation: bounce 0.6s ease;">🛡️</div>
    <div style="flex: 1; min-width: 0;">
      <div style="font-weight: 700; font-size: 14px; margin-bottom: 6px; letter-spacing: 0.3px;">
        ${D(o.type)} · ${o.level.toUpperCase()}
      </div>
      <div style="font-size: 13px; word-break: break-word; line-height: 1.6; opacity: 0.95;">${o.description}</div>
      <div style="margin-top: 8px; font-size: 11px; opacity: 0.8; font-weight: 500;">
        📍 ${t}
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
    `,document.head.appendChild(l)}const r=n.querySelector("button");r?.addEventListener("mouseenter",()=>{r instanceof HTMLElement&&(r.style.background="rgba(255,255,255,0.3)",r.style.transform="scale(1.1)")}),r?.addEventListener("mouseleave",()=>{r instanceof HTMLElement&&(r.style.background="rgba(255,255,255,0.2)",r.style.transform="scale(1)")}),r?.addEventListener("click",l=>{l.stopPropagation(),n.style.opacity="0",n.style.transform="translateX(400px) scale(0.8)",setTimeout(()=>n.remove(),400)}),i.appendChild(n),requestAnimationFrame(()=>{requestAnimationFrame(()=>{n.style.opacity="1",n.style.transform="translateX(0) scale(1)"})}),setTimeout(()=>{n.style.opacity="0",n.style.transform="translateX(400px) scale(0.8)",setTimeout(()=>n.remove(),400)},6e3)}function G(){if(!p.length)return;const o=[...p];p.length=0,o.forEach(x)}function h(o,t={}){f||(console.warn("🚨 威胁检测:",{类型:D(o.type),等级:o.level.toUpperCase(),描述:o.description,详情:o.details}),x(o),t.notifyBackground&&N(o))}const y=document.createElement("meta");y.name="web-security-guardian";y.content="active";document.head?.appendChild(y);window.webSecurityGuardian={version:"1.0.0",isActive:!0,reportThreat:o=>{const t={id:o.id||_(),type:o.type||c.DATA_LEAK,level:o.level||a.MEDIUM,url:o.url||window.location.href,description:o.description||"检测到未知安全威胁",timestamp:o.timestamp||Date.now(),blocked:o.blocked??!1,details:o.details};h(t,{notifyBackground:!0})}};function I(o,t){try{const e=new URL(o,window.location.href).href,i=R(e);if(i.detected){const n={id:_(),type:c.PHISHING,level:i.score>=80?a.CRITICAL:a.HIGH,url:e,description:`检测到疑似钓鱼链接（来源：${t}）`,timestamp:Date.now(),blocked:!0,details:{reasons:i.reasons,score:i.score,source:t}};return h(n,{notifyBackground:!0}),console.warn("🎣 钓鱼风险详情:",i.reasons),!0}}catch(e){console.warn("无法解析URL进行安全检查:",o,e)}return!1}function j(){document.addEventListener("click",o=>{if(!(o.target instanceof Element))return;const t=o.target.closest("a[href]");if(!t)return;const e=t.href;I(e,"anchor_click")&&(o.preventDefault(),o.stopImmediatePropagation())},!0)}function B(){const o=window.open;window.open=function(...t){const e=t[0],i=typeof e=="string"?e:e?.toString?.();return typeof i=="string"&&I(i,"window.open")?null:o.apply(window,t)}}async function E(){if(G(),await P()){console.log("⏸️ 白名单网站，已禁用所有安全检测");return}k()&&chrome.runtime.sendMessage({type:"PAGE_NAVIGATION",url:window.location.href}).then(n=>{n?.clearedCount>0&&console.log(`🗑️ 已清除 ${n.clearedCount} 条历史威胁，开始重新评估`)}).catch(n=>console.error("Failed to notify page navigation:",n));let t=!1;function e(){t||(t=!0,b.setThreatCallback(n=>h(n,{notifyBackground:!0})),b.initialize(),S.setThreatCallback(n=>h(n,{notifyBackground:!0})),S.initialize(),T.setThreatCallback(n=>h(n,{notifyBackground:!0})),T.initialize(),console.log("✅ 监控器已启动"))}function i(){f||(g||(g=!0,console.log("👆 检测到用户交互，启动监控"),e()),w&&clearTimeout(w),w=window.setTimeout(()=>{g=!1,console.log("⏸️ 用户交互超时，暂停监控")},5e3))}document.addEventListener("click",i,!0),document.addEventListener("submit",i,!0),document.addEventListener("keydown",n=>{n.key==="Enter"&&i()},!0),H.initialize(),j(),console.log("✅ Web Security Guardian 内容脚本已激活（实时监控模式）")}B();document.readyState==="loading"?document.addEventListener("DOMContentLoaded",E):E();
