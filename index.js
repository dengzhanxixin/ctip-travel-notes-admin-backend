const CORS = require("cors");
const User = require("./models/User");
const Task = require("./models/Task");
const express = require("express");
const app = express();
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const mongoose = require("mongoose");
const port = 8080;

const session = require("express-session");
const cookieParser = require("cookie-parser");

// app.use(CORS());
const corsOptions = {
  // origin: '*',
  origin: "http://localhost:3000",
  credentials: true,
};
app.use(CORS(corsOptions));

app.use(cookieParser());
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }, // 对于HTTPS设置为true
  })
);

// 连接到MongoDB数据库
mongoose
  .connect("mongodb://localhost/testDataBase", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB...")) // 连接成功
  .catch((err) => console.error("Could not connect to MongoDB...", err)); // 连接失败

app.use(bodyParser.json());

// 一个简单的路由，确认服务器运行正常
app.get("/", (req, res) => {
  res.send("Hello World!");
});

// 用于创建标准化错误响应的工具函数
const createErrorResponse = (message) => {
  return JSON.stringify({
    success: false,
    message,
  });
};

app.get("/menus", async (req, res) => {
  try {
    // 更新的菜单数据，包含子菜单项
    const menus = [
      {
        id: 1,
        authName: "主页",
        path: "/home",
        children: [
          {
            id: 11,
            authName: "主页概览",
            path: "/home/home",
          },
        ],
      },
      {
        id: 2,
        authName: "用户",
        path: "/home/user",
        children: [
          {
            id: 21,
            authName: "用户管理",
            path: "/home/user",
          },
        ],
      },
      {
        id: 3,
        authName: "任务",
        path: "/home/task",
        children: [
          {
            id: 31,
            authName: "任务详情",
            path: "/home/task",
          },
        ],
      },
    ];

    // 直接返回菜单数据
    res
      .status(200)
      .json({ meta: { status: 200, msg: "获取菜单列表成功" }, data: menus });
  } catch (error) {
    // 如果有错误，返回500状态码和错误信息
    res
      .status(500)
      .send({ meta: { status: 500, msg: "获取菜单列表失败" }, error: error });
  }
});

// 注册路由
app.post("/register", async (req, res) => {
  console.log("Received request body:", req.body);
  try {
    let { username, password } = req.body;
    // 确保 username 和 password 都是字符串
    username = String(username);
    password = String(password);
    console.log(
      `后端拿到的注册的账号密码 ${
        req.body
      } 账号 ${username} ${typeof username}  密码 ${password} ${typeof password}`
    );
    // 对密码进行加密处理
    // const hashedPassword = await bcrypt.hash(password, 12);
    // 创建新用户并保存到数据库中
    // const newUser = new User({ username, password: hashedPassword });
    const newUser = new User({ username, password });
    await newUser.save();
    res.status(201).send({ success: true, message: "用户注册成功" });
  } catch (error) {
    console.error("注册错误:", error); // 记录完整的错误信息
    res.status(500).send({ success: false, message: "用户注册失败" + error });
  }
});

// 登录路由
app.post("/login", async (req, res) => {
  let { username, password } = req.body;
  username = String(username);
  password = String(password);
  console.log(
    `后端拿到的登陆的账号密码 ${
      req.body
    } 账号 ${username} ${typeof username}  密码 ${password} ${typeof password}`
  );
  // 在数据库中查找用户信息
  const user = await User.findOne({ username });
  if (!user) {
    // 用户不存在
    return res.status(401).send("用户名不存在");
  }
  console.log(
    `此时对应正确的账号密码 账号 ${user.username} 密码 ${
      user.password
    } 输入的密码加密后${bcrypt.compare(password, user.password)}`
  );
  // 验证密码
  const isMatch = await user.comparePassword(password);

  if (!isMatch) {
    // 密码不匹配
    return res.status(401).send("用户名或密码不正确");
  }

  const token = "generated-token-for-demo";

  // 设置 session 和 cookie
  req.session.userId = user._id;
  // 设置httpOnly和secure选项的cookie
  // res.cookie('token', token, { httpOnly: false, secure: false, sameSite: 'Strict', maxAge: 3600000 });

  // 设置cookie
  res.cookie("isLoggedIn", "true", {
    httpOnly: false, // 增加安全性，防止客户端脚本访问cookie
    secure: false, // 对于HTTPS设置
    maxAge: 3600000, // 设置cookie的过期时间，例如1小时
  });

  // 返回 JSON 响应
  res.json({
    success: true,
    message: "登录成功",
    token: token, // 实际应用中返回给前端的认证令牌
    meta: {
      status: 200,
      id: user._id, // 可以返回用户的一些安全的信息，不要返回密码等敏感信息
      role: user.role,
      username: user.username,
    },
  });
});

// 获取任务列表
app.get("/tasks", async (req, res) => {
  try {
    const { pagenum, pagesize } = req.query;
    const query = Task.find();
    const total = await Task.countDocuments();

    if (pagenum && pagesize) {
      query.skip((pagenum - 1) * pagesize).limit(parseInt(pagesize));
    }

    const tasks = await query.exec();

    res.json({
      meta: {
        status: 200,
        msg: "获取任务列表成功",
      },
      data: {
        tasks: tasks,
        total: total,
      },
    });
  } catch (error) {
    console.error("获取任务列表失败:", error);
    res
      .status(500)
      .json({ meta: { status: 500, msg: "获取任务列表失败" }, error: error });
  }
});

// 添加新任务
app.post("/tasks", async (req, res) => {
  try {
    // 首先找到当前最大的 taskNumber
    const latestTask = await Task.findOne().sort({ taskNumber: -1 });
    let newTaskNumber = 1;
    if (latestTask) {
      // 如果存在，将字符串形式的 taskNumber 转换为数字，并加 1
      newTaskNumber = parseInt(latestTask.taskNumber, 10) + 1;
    }

    // 使用新的 taskNumber 创建任务
    const { details, time, completed } = req.body;
    const newTask = new Task({
      taskNumber: newTaskNumber,
      details,
      time,
      completed,
    });

    await newTask.save(); // 保存新任务到数据库
    res
      .status(201)
      .json({ meta: { status: 201, msg: "添加任务成功" }, data: newTask });
  } catch (error) {
    console.error("添加任务失败:", error);
    res.status(500).json({
      meta: { status: 500, msg: "添加任务失败" },
      error: error.message,
    });
  }
});

// 删除任务的路由
app.delete("/tasks/:taskNumber", async (req, res) => {
  const { taskNumber } = req.params;
  try {
    // 查找并删除任务
    const deletedTask = await Task.findOneAndDelete({
      taskNumber: parseInt(taskNumber, 10),
    });
    if (deletedTask) {
      res.status(200).json({
        meta: { status: 200, msg: "任务删除成功" },
        data: deletedTask,
      });
    } else {
      // 如果没有找到任务，返回 404
      res.status(404).json({ meta: { status: 404, msg: "未找到任务" } });
    }
  } catch (error) {
    console.error("删除任务失败:", error);
    res.status(500).json({
      meta: { status: 500, msg: "删除任务失败" },
      error: error.message,
    });
  }
});

// 更新任务
app.patch("/tasks/:taskNumber", async (req, res) => {
  const { taskNumber } = req.params;
  console.error("更新任务的时候拿到的数据:", req, res);
  try {
    // 使用 taskNumber 查找任务并更新
    const updatedTask = await Task.findOneAndUpdate(
      { taskNumber: parseInt(taskNumber, 10) }, // 查找条件
      req.body, // 更新内容
      { new: true } // 返回更新后的文档
    );

    if (updatedTask) {
      res.status(200).json({
        meta: { status: 200, msg: "任务更新成功" },
        data: updatedTask,
      });
    } else {
      // 如果没有找到任务，返回 404
      res.status(404).json({ meta: { status: 404, msg: "未找到任务" } });
    }
  } catch (error) {
    console.error("更新任务失败:", error);
    res.status(500).json({
      meta: { status: 500, msg: "更新任务失败" },
      error: error.message,
    });
  }
});

// 获取用户列表
app.get("/people", async (req, res) => {
  try {
    console.error("收到了要去拿user相关信息的请求");
    const users = await User.find().select("-password"); // 排除密码字段
    console.error("收到了要去拿user相关信息的请求后拿到的数据是", users);
    res.json({ success: true, data: users });
  } catch (error) {
    console.error("获取用户列表失败:", error);
    res
      .status(500)
      .json({ success: false, message: "获取用户列表失败", error });
  }
});

// 添加新用户
app.post("/people", async (req, res) => {
  try {
    const { username, password, email, mobile, role } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ success: false, message: "用户已存在" });
    }

    const newUser = new User({ username, password, email, mobile, role });
    await newUser.save();

    res
      .status(201)
      .json({ success: true, message: "用户添加成功", data: newUser });
  } catch (error) {
    console.error("添加用户失败:", error);
    res.status(500).json({ success: false, message: "添加用户失败", error });
  }
});

// 为用户分配角色
app.post("/assign-role", async (req, res) => {
  const { userId, role } = req.body;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send("用户未找到");
    }
    user.role = role;
    await user.save();
    res.send({ success: true, message: "角色分配成功" });
  } catch (error) {
    console.error(error);
    res.status(500).send("内部服务器错误");
  }
});

// 启动服务器
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
