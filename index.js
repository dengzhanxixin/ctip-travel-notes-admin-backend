const CORS = require("cors");
const User = require("./models/User");
const express = require("express");
const app = express();
const axios = require("axios");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const port = 8080;

const cookieParser = require("cookie-parser");
const { readDataFromFile, writeDataToFile } = require("./fileDataManager");

const jwt = require("jsonwebtoken");
const SECRET_KEY = "ctip_yhr_secret_key"; // 请在生产环境中使用更安全的密钥
const { v4: uuidv4 } = require("uuid");

const corsOptions = {
  // origin: '*',
  origin: "http://localhost:3000",
  credentials: true,
};
app.use(CORS(corsOptions));
app.use(cookieParser());
app.use(bodyParser.json());

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
        authName: "游记",
        path: "/home/task",
        children: [
          {
            id: 31,
            authName: "游记详情",
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
  let { username, password } = req.body;
  username = String(username);
  password = String(password);
  console.log(
    `后端拿到的注册的账号密码 ${
      req.body
    } 账号 ${username} ${typeof username}  密码 ${password} ${typeof password}`
  );

  const users = readDataFromFile("users.json");

  // 检查用户是否已存在
  const userExists = users.some((user) => user.username === username);
  if (userExists) {
    return res.status(400).json({ success: false, message: "用户已存在" });
  }

  // 对密码进行加密
  const hashedPassword = await bcrypt.hash(password, 10);

  // 使用UUID生成唯一的用户id
  const newUser = {
    id: uuidv4(),
    username,
    password: hashedPassword,
    role: "root_admin",
  };
  users.push(newUser);

  // 写入文件
  writeDataToFile("users.json", users);

  res
    .status(201)
    .json({ success: true, message: "注册成功", userId: newUser.id });
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
  const users = readDataFromFile("users.json");

  // 查找用户
  const user = users.find((u) => u.username === username);
  if (!user) {
    return res
      .status(401)
      .json({ success: false, message: "用户名或密码不正确" });
  }

  // 验证密码
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res
      .status(401)
      .json({ success: false, message: "用户名或密码不正确" });
  }

  // 生成JWT
  const token = jwt.sign(
    { userId: user.id, username: user.username },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  // 返回成功响应和JWT
  res.json({
    success: true,
    message: "登录成功",
    token: token,
    role: user.role, 
  });
});

// 获取用户列表的接口
app.get("/people", (req, res) => {
  const users = readDataFromFile("users.json");
  // 返回除密码外的用户信息
  const usersInfo = users.map(({ password, ...rest }) => rest);
  res.json({ success: true, data: usersInfo });
});

// 分配角色的接口
app.post("/assign-role", (req, res) => {
  const { userId, role } = req.body;
  let users = readDataFromFile("users.json");

  const userIndex = users.findIndex((user) => user.id === userId);
  if (userIndex === -1) {
    console.log(`分配的角色不存在 ${password} ${typeof password}`);
    return res.status(404).json({ success: false, message: "用户不存在" });
  }
  console.log(`分配的角色 ${userId} 为角色 ${role}`);
  // 更新用户角色
  users[userIndex].role = role;
  writeDataToFile("users.json", users);

  res.json({ success: true, message: "角色分配成功" });
});

app.get("/all-travel-data", (req, res) => {
  const allData = readDataFromFile("totalTravelData.json");

  // 提取所需的字段
  const requiredData = allData.map(
    ({
      id,
      title,
      user,
      traffic,
      img_Intrinsic,
      isChecked,
      detail: { summary, images },
    }) => {
      // 从 img 对象中提取所有的图片 URL
      const imgs = Object.values(images).map((imgDetail) => imgDetail.url);

      return {
        id,
        title,
        user,
        traffic,
        img_Intrinsic,
        isChecked,
        summary,
        imgs
      };
    }
  );

  res.json({ success: true, data: requiredData });
});

// 审核游记的接口
app.post("/audit-travel", (req, res) => {
  let { id, isChecked, reason } = req.body;
  isChecked = Number(isChecked); // 将 isChecked 转换为数字
  console.log("后端收到的数据", req.body);
  // 读取当前所有游记数据
  let travelData = readDataFromFile("totalTravelData.json");

  // 查找对应ID的游记
  const dataIndex = travelData.findIndex((data) => data.id === id);
  if (dataIndex === -1) {
    console.log("没有找到对应游记");
    // 如果找不到，返回错误信息
    return res
      .status(404)
      .json({ success: false, message: "未找到对应的游记" });
  }

  // 更新游记的审核状态和驳回理由
  travelData[dataIndex].isChecked = isChecked;
  if (isChecked === 2) {
    console.log("添加驳回理由", reason);
    // 如果是驳回状态，添加驳回理由
    travelData[dataIndex].reason = reason;
  }

  // 写回修改后的数据到文件
  writeDataToFile("totalTravelData.json", travelData);

  // 返回成功响应
  res.json({ success: true, message: "游记审核状态更新成功" });
});

// 删除游记的接口
app.delete("/delete-travel/:id", (req, res) => {
  const { id } = req.params; // 从请求URL中获取游记的ID
  console.log("后端收到的数据", req.params);
  let travelData = readDataFromFile("totalTravelData.json");

  // 查找并删除指定ID的游记
  const dataIndex = travelData.findIndex((travel) => travel.id === id);
  if (dataIndex === -1) {
    console.log("没有找到对应游记");
    return res
      .status(404)
      .json({ success: false, message: "未找到对应的游记" });
  }

  // 更新游记的审核状态和驳回理由
  travelData[dataIndex].isChecked = 3;

  // 保存更新后的数据回文件
  writeDataToFile("totalTravelData.json", travelData);

  // 返回成功响应
  res.json({ success: true, message: "游记已删除" });
});

// 启动服务器
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
