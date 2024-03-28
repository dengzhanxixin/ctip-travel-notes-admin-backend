# 项目简介

本项目是一个基于React和Express的全栈应用，实现了用户登录、权限管理、列表展示和表单提交等功能。它采用了Ant Design来提升用户界面和用户体验。**基于2024携程前端训练营第四课作业的基础上开发。**

## 技术栈

- 前端
  - React：用于构建用户界面的JavaScript库。
  - Ant Design：一套企业级的UI设计语言和React实现。
  - Cookies：在客户端存储会话信息。
  - Axios：用于浏览器和node.js的基于Promise的HTTP客户端。
- 后端
  - Express：快速、无约束的Node.js web应用框架。
  - Mongoose：MongoDB的对象数据模型(ODM)库，用于在异步环境下工作。
  - bcryptjs：用于密码的加密和校验。
  - cookie-parser和express-session：用于处理会话和cookie。

- 数据库
  - MongoDB：面向文档的数据库管理系统，不需要预定义模式。

## 主要功能

1. **登录功能**：
   - 使用Cookies来存储会话信息，实现记住登录状态，避免用户重复登录。
   - 密码在数据库中以加密形式存储，保障用户信息安全。

2. **权限管理**：
   - 设计用户角色模型，通过用户的角色来控制访问权限。
   - 实现了给用户分配角色的后台逻辑。

3. **列表页和表单填写页**：
   - 利用Ant Design构建了列表页和表单填写页的UI。
   - 实现了任务列表的展示、添加新任务、编辑任务和删除任务的功能。
   - 提供了用户管理页面，展示用户列表和分配用户角色的功能。

## 如何运行

### 启动后端服务（端口8080）

```
node index.js
```

### 启动前端应用（端口3000）

在另一个终端窗口，导航到前端项目目录，然后运行：

```
npm start
```

浏览器会自动打开`http://localhost:3000`，并显示应用。

## 项目结构

- `pages`：包含了登录页、首页以及其他页面组件。
- `models`：定义了用户和任务的数据模型。
- `service`：封装了与后端交互的服务方法。
- `index.js`：后端的入口文件，定义了 API 路由和中间件。

## 项目运行

1. 启动后端服务器

```
cd backend
npm install
npm start
```

2. 启动前端项目

```
cd frontend
npm install --force
npm start
```

## 结语

本项目实现了一个基本的任务管理系统，包括用户注册、登录、任务的增删改查等功能，通过MongoDB进行数据存储，利用React和Ant Design构建前端界面，实现了一个简洁美观且功能完备的管理系统。

