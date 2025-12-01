# 🛡️ Web Security Guardian

一个基于 Vue 3 + TypeScript 开发的现代化浏览器安全防护插件，为用户提供全面的 Web 应用层安全防护。

## ✨ 主要功能

- 🚫 **恶意 URL 检测与阻止** - 实时识别并拦截已知恶意网站
- ⚠️ **XSS 攻击防护** - 检测并阻止跨站脚本攻击
- 👁️ **隐私追踪器阻止** - 拦截第三方追踪脚本，保护用户隐私
- 🔒 **表单安全检查** - 检测 SQL 注入、敏感数据泄露风险
- 🎣 **钓鱼网站识别** - 智能识别仿冒网站
- 🤖 **AI 钓鱼检测** - 集成免费 AI 模型进行智能网址分析
- 📊 **可视化统计分析** - 多维度图表展示安全数据
- 🎯 **用户交互式监控** - 仅在用户操作时启动检测，零性能损耗

## 🛠️ 技术栈

### 前端框架
- **Vue 3** - 渐进式 JavaScript 框架
- **TypeScript** - 类型安全的 JavaScript 超集
- **Vite** - 下一代前端构建工具

### UI 组件库
- **Element Plus** - 基于 Vue 3 的组件库
- **ECharts** - 专业的数据可视化图表库

### 状态管理
- **Pinia** - Vue 3 官方推荐的状态管理库

### 浏览器扩展
- **Chrome Extensions API (Manifest V3)** - 最新版扩展 API
- **Content Scripts** - 页面内容脚本注入
- **Background Service Worker** - 后台服务工作线程

### AI 集成
- **OpenRouter API** - 免费 AI 模型接口
- **DeepSeek R1T2 Chimera** - 智能钓鱼网站检测

## 📦 项目结构

```
web_sec/
├── src/
│   ├── background/          # 后台脚本
│   │   └── index.ts         # Service Worker 主文件
│   ├── content/             # 内容脚本
│   │   ├── index.ts         # 内容脚本入口
│   │   ├── dom-observer.ts  # DOM 监控
│   │   ├── form-monitor.ts  # 表单监控
│   │   ├── script-monitor.ts # 脚本监控
│   │   └── page-analyzer.ts # 页面分析
│   ├── popup/               # 插件弹窗
│   │   ├── App.vue          # 弹窗主组件
│   │   └── index.html       # 弹窗页面
│   ├── options/             # 设置页面
│   │   ├── App.vue          # 设置主组件
│   │   └── index.html       # 设置页面
│   ├── views/               # 测试页面
│   │   └── HomeView.vue     # 危险行为测试页
│   ├── stores/              # 状态管理
│   │   └── security.ts      # 安全状态
│   ├── types/               # 类型定义
│   │   └── index.ts         # 通用类型
│   └── utils/               # 工具函数
│       └── storage.ts       # 存储工具
├── public/                  # 静态资源
│   └── rules/               # 规则配置
│       ├── malicious-urls.json
│       └── tracker-blocking.json
├── dist-extension/          # 插件构建输出
└── package.json
```

## 🚀 从零运行项目

### 环境要求

- **Node.js**: `^20.19.0` 或 `>=22.12.0`
- **npm**: 最新版本

### 1. 克隆项目

```bash
git clone <your-repository-url>
cd web_sec
```

### 2. 安装依赖

```bash
npm install
```

### 3. 运行开发服务器（测试页面）

```bash
npm run dev
```

访问 `http://localhost:5173/` 查看危险行为测试页面。

### 4. 构建浏览器插件

```bash
npm run build:extension
```

构建完成后，插件文件将输出到 `dist-extension/` 目录。

## 🔌 安装插件到浏览器

### Chrome 浏览器

1. 打开浏览器，进入扩展程序管理页面：
   - Chrome: `chrome://extensions/`

2. 开启右上角的 **"开发者模式"**

3. 点击 **"加载已解压的扩展程序"**

4. 选择项目中的 `dist-extension/` 文件夹

5. 插件安装成功！图标将出现在浏览器工具栏

### 使用插件

- **查看安全状态**: 点击工具栏插件图标
- **AI 钓鱼检测**: 在弹窗中点击"AI 检测"按钮
- **查看统计图表**: 右键插件图标 → 选项 → 统计信息
- **配置防护规则**: 右键插件图标 → 选项 → 基本设置

## 📋 实现内容说明

### 核心安全检测

#### 1. XSS 攻击检测
- **Script 标签注入检测**
- **事件处理器注入检测** (`onerror`, `onload` 等)
- **JavaScript 伪协议检测** (`javascript:`)
- **危险函数拦截** (`eval()`, `Function()`, `setTimeout(string)`)
- **DOM XSS 监控**

#### 2. SQL 注入检测
- 表单输入内容分析
- 常见 SQL 注入模式识别
- 实时输入验证

#### 3. 恶意 URL 防护
- 基于规则库的 URL 黑名单
- 动态脚本来源检测
- 隐藏 iframe 注入检测

#### 4. 隐私追踪器阻止
- Google Analytics
- Facebook Pixel
- Mixpanel
- 其他常见追踪器

#### 5. 表单安全检查
- HTTP 表单敏感数据提交警告
- 邮箱、手机号、身份证、信用卡号检测
- 表单提交拦截机制

#### 6. 钓鱼网站检测
- 域名相似度分析
- 可疑关键词检测
- AI 智能分析（集成 OpenRouter API）

### 高级特性

#### 用户交互式监控
- **零初始负载**: 页面加载时不执行检测
- **按需启动**: 仅在用户点击、提交、按键时激活
- **性能优化**: 避免误报和性能影响
- **智能超时**: 5 秒无操作自动暂停监控

#### 威胁去重与管理
- 每个威胁独立上报
- 实时 Toast 通知
- 页面切换自动清理历史威胁
- 按页面维度统计评分

#### 数据可视化
- **饼图**: 威胁类型分布
- **柱状图**: 威胁类型统计
- **环形图**: 威胁等级分布
- **雷达图**: 安全防护能力评估

#### AI 增强
- 集成 OpenRouter 免费 API
- DeepSeek R1T2 Chimera 模型
- 多维度 URL 安全分析
- 智能判断钓鱼风险

### 白名单机制

为避免误报，插件内置了可信域名白名单：
- 常见 CDN（cdnjs, jsdelivr, unpkg）
- 大型网站资源域（twimg.com, gstatic.com, fbcdn.net）
- 当前页面同域资源

## 📊 可用脚本

```bash
# 开发服务器（测试页面）
npm run dev

# 构建测试页面
npm run build

# 构建浏览器插件
npm run build:extension

# 类型检查
npm run type-check

# 代码检查
npm run lint
```

## 🧪 测试页面功能

访问 `http://localhost:5173/` 可测试以下场景：

1. **恶意 URL 访问测试**
2. **XSS 攻击检测测试**
3. **SQL 注入检测测试**
4. **敏感信息泄露检测**
5. **恶意脚本注入检测**
6. **混淆代码检测**
7. **第三方追踪器阻止测试**
8. **钓鱼网站检测测试**

## ⚙️ 配置说明

### AI API 配置

编辑 `src/popup/App.vue` 第 312 行，替换为你的 OpenRouter API Key：

```typescript
const apiKey = 'your-openrouter-api-key'
```

获取免费 API Key：https://openrouter.ai/

### 规则库配置

- **恶意 URL 规则**: `public/rules/malicious-urls.json`
- **追踪器规则**: `public/rules/tracker-blocking.json`

## 🔒 安全说明

- 本插件仅用于学习和研究目的
- 测试页面包含模拟的危险行为，请勿在生产环境部署
- 所有检测均在本地进行，不会上传用户数据
- AI 检测功能需要网络连接到 OpenRouter API

## 📝 开发说明

### 添加新的威胁检测规则

1. 在 `src/types/index.ts` 中定义新的威胁类型
2. 在对应的监控模块中实现检测逻辑
3. 通过 `handleThreat()` 上报威胁
4. 在 `src/background/index.ts` 中处理威胁统计

### 自定义 Toast 样式

编辑 `src/content/index.ts` 中的 `createToastElement()` 函数。

---

**⚠️ 免责声明**: 本项目仅供学习和研究使用，请勿用于非法用途。使用本插件产生的任何后果由使用者自行承担。
