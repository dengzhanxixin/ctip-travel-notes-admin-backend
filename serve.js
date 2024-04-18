const express = require("express");
const app = express();
const CORS = require("cors");
const bodyParser = require("body-parser");
const fs = require("fs");
const bcrypt = require("bcrypt");
const axios = require("axios");
// sha1加密
const sha1 = require("sha1");

const saltRounds = 10; // 定义salt的回合数，推荐值

const cookieParser = require("cookie-parser");
const { readDataFromFile, writeDataToFile } = require("./fileDataManager");

const path = require("path");
// 进入 data 目录
const dataPath = path.join(__dirname, "..", "data", "user.json");
const jwt = require("jsonwebtoken");
const SECRET_KEY = "ctrip_yhr_secret_key"; // 用于JWT加密的密钥，应保持安全

const { v4: uuidv4 } = require("uuid");
const { MongoClient } = require("mongodb");
const MONGO_URI = "mongodb://localhost:27017"; // MongoDB连接URI
const DB_NAME = "yhr_mongoDB"; // 数据库名称
// 连接MongoDB数据库
const client = new MongoClient(MONGO_URI);

const port = 3001;

app.use(express.json()); // 用于解析JSON的中间件
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

// 在 Express 应用中添加 CORS 头部
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});
// 身份验证
function authenticate(req, res, next) {
  console.log("后端权限验证");
  const token = req.cookies.token;
  if (!token) {
    console.log("后端权限验证结果:No token provided");
    return res.status(403).json({ message: "No token provided." });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    console.log("后端权限验证结果:Invalid token.");
    return res.status(401).json({ message: "Invalid token." });
  }
}
// 权限验证
function checkSuperAdmin(req, res, next) {
  console.log("superadmin验证");
  if (req.user.role === "super_admin") {
    console.log("superadmin验证成功，调用接口");
    next();
  } else {
    console.log("superadmin验证失败，不是super_admin");
    return res
      .status(403)
      .json({ message: "You do not have permission to access this resource." });
  }
}

// 连接MongoDB数据库
async function connectToDatabase() {
  try {
    await client.connect();
    console.log("Connected to the database");
  } catch (error) {
    console.error("Error connecting to the database:", error);
  }
}

connectToDatabase(); // 连接数据库

const corsOptions = {
  // origin: "*",
  // origin: "http://localhost:3000",
  origin: ["http://localhost:3000","http://114.55.113.21:2000", "http://114.55.113.21:3000"], // 允许这些域进行跨域请求
  credentials: true, // 允许跨域请求携带cookies
};
app.use(CORS(corsOptions));
app.use(cookieParser());
app.use(bodyParser.json());

// 管理系统
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

// 注册路由（在 MongoDB 中新增）
app.post("/register", async (req, res) => {
  let { username, password } = req.body;
  username = String(username);
  password = String(password);
  console.log(
    `从前端拿到的注册的账号密码 ${JSON.stringify(
      req.body
    )} 账号 ${username} 密码 ${password}`
  );
  try {
    const db = client.db(DB_NAME);
    const usersCollection = db.collection("users");

    // 检查用户是否已存在
    const existingUser = await usersCollection.findOne({ username });
    if (existingUser) {
      console.log("用户已存在");
      return res.status(400).json({ success: false, message: "用户已存在" });
    }

    // 对密码进行加密
    const hashedPassword = await bcrypt.hash(password, 10);

    // 判断用户名并设置角色
    let role = "user";
    if (username === "admin" || username === "ctrip") {
      role = "super_admin";
    }

    // 使用UUID生成唯一的用户id
    const newUser = {
      id: uuidv4(),
      username,
      password: hashedPassword,
      role: role,
    };

    // 插入新用户到数据库
    await usersCollection.insertOne(newUser);

    console.log("注册成功");
    res
      .status(201)
      .json({ success: true, message: "注册成功", userId: newUser.id });
  } catch (error) {
    console.error("注册失败:", error);
    res.status(500).json({ success: false, message: "注册失败" });
  }
});

// 登录路由（从 MongoDB 中校验）
app.post("/login", async (req, res) => {
  let { username, password } = req.body;
  username = String(username);
  password = String(password);

  console.log(
    `从前端拿到的登陆的账号密码 ${JSON.stringify(
      req.body
    )} 账号 ${username} 密码 ${password}`
  );
  try {
    const db = client.db(DB_NAME);
    const usersCollection = db.collection("users");

    // 查找用户
    const user = await usersCollection.findOne({ username });
    if (!user) {
      console.log("用户名或密码不正确");
      return res
        .status(401)
        .json({ success: false, message: "用户名或密码不正确" });
    }

    // 验证密码
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log("用户名或密码不正确");
      return res
        .status(401)
        .json({ success: false, message: "用户名或密码不正确" });
    }

    // 生成JWT
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    console.log("登录成功");
    // 设置HttpOnly Cookie
    res.cookie("token", token, {
      httpOnly: true, // JavaScript无法访问Cookie
      secure: false, // 是否通过HTTPS发送
      maxAge: 3600000, // Cookie有效期，与token的过期时间相同
    });
    // 返回成功响应和JWT
    res.json({
      success: true,
      message: "登录成功",
      // token: token,
      // role: user.role,
    });
  } catch (error) {
    console.error("登录失败:", error);
    res.status(500).json({ success: false, message: "登录失败" });
  }
});

// 获取用户列表的接口（从 MongoDB 中获取）
app.get("/people", authenticate, async (req, res) => {
  try {
    const db = client.db(DB_NAME);
    const usersCollection = db.collection("users");

    // 查询所有管理员的信息
    const users = await usersCollection.find().toArray();

    // 返回除密码外的管理员信息
    const adminsInfo = users.map(({ password, ...rest }) => rest);
    res.json({ success: true, data: adminsInfo });
  } catch (error) {
    console.error("获取管理员列表失败:", error);
    res.status(500).json({ success: false, message: "获取管理员列表失败" });
  }
});

// 分配角色的接口（从 MongoDB 中更新）
app.post("/assign-role", authenticate, checkSuperAdmin, async (req, res) => {
  const { userId, role } = req.body;

  try {
    const db = client.db(DB_NAME);
    const usersCollection = db.collection("users");

    // 查找并更新用户角色
    const result = await usersCollection.updateOne(
      { id: userId },
      { $set: { role: role } }
    );

    // 检查是否找到并更新了用户
    if (result.matchedCount === 0) {
      console.log(`分配的角色不存在 ${userId}`);
      return res.status(404).json({ success: false, message: "用户不存在" });
    }

    console.log(`分配的角色 ${userId} 为角色 ${role}`);
    res.json({ success: true, message: "角色分配成功" });
  } catch (error) {
    console.error("分配角色失败:", error);
    res.status(500).json({ success: false, message: "角色分配失败" });
  }
});

// 获取所有游记的接口
app.get("/all-travel-data", authenticate, (req, res) => {
  const allData = readDataFromFile("TravelData.json");
  console.log("前端请求所有的游记数据");
  const baseURL = "http://114.55.113.21/frontend/public"; // 指向公共图片目录的基础URL
  // 提取所需的字段
  const requiredData = allData.map(
    ({
      id,
      title,
      user,
      city,
      coverImg,
      isChecked,
      content,
      publishDisplayTime,
      images,
    }) => {
      // 从 img 对象中提取所有的图片 URL
      const imgs = Object.values(images).map((imgDetail) => {
        // 检查是否是完整的 URL
        return imgDetail.url.startsWith("http")
          ? imgDetail.url
          : `${baseURL}${imgDetail.url}`;
      });

      // 对 coverImg 进行同样的处理
      const fullCoverImg = coverImg.startsWith("http")
        ? coverImg
        : `${baseURL}${coverImg}`;

      return {
        id,
        title,
        user,
        city,
        coverImg: fullCoverImg,
        isChecked,
        content,
        publishDisplayTime,
        imgs,
      };
    }
  );
  // console.log('后端返回的所有的游记数据',requiredData)
  res.json({ success: true, data: requiredData });
});

// 审核游记的接口
app.post("/audit-travel", authenticate, (req, res) => {
  let { id, isChecked, checkReason } = req.body;
  isChecked = Number(isChecked); // 将 isChecked 转换为数字
  console.log("后端收到的数据", req.body);
  // 读取当前所有游记数据
  let travelData = readDataFromFile("TravelData.json");

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
    console.log("添加驳回理由", checkReason);
    // 如果是驳回状态，添加驳回理由
    travelData[dataIndex].checkReason = checkReason;
  }

  // 写回修改后的数据到文件
  writeDataToFile("TravelData.json", travelData);

  // 返回成功响应
  res.json({ success: true, message: "游记审核状态更新成功" });
});

// 删除游记的接口
app.delete("/delete-travel/:id", authenticate, checkSuperAdmin, (req, res) => {
  const { id } = req.params; // 从请求URL中获取游记的ID
  console.log("后端收到的数据", req.params);
  let travelData = readDataFromFile("TravelData.json");

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
  writeDataToFile("TravelData.json", travelData);

  // 返回成功响应
  res.json({ success: true, message: "游记已删除" });
});

// 用户系统
// 用户注册
app.post("/api/register", async (req, res) => {
  const { username, password, avatar, likeNote, saveNote, followUser } =
    req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "需要用户名和密码" });
  }

  const users = JSON.parse(fs.readFileSync(dataPath, "utf8"));

  if (users.some((user) => user.username === username)) {
    return res.status(400).json({ message: "用户名已存在" });
  }

  // 对密码进行加密
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  const newUser = {
    id: users.length + 1,
    username,
    password: hashedPassword, // 存储加密后的密码
    avatar,
    likeNote,
    saveNote,
    followUser,
  };

  users.push(newUser);
  fs.writeFileSync(dataPath, JSON.stringify(users, null, 2));

  res.status(201).json({ message: "用户创建成功" });
});

app.get("/api/check-avatar", (req, res) => {
  const username = req.query.username; // 从请求中获取用户名
  const filePath = path.join(__dirname, "images", `${username}_avatar.jpg`);
  if (fs.existsSync(filePath)) {
    res.json({ success: true, avatar: filePath });
  } else {
    res.json({ success: false, avatar: null });
  }
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const users = JSON.parse(fs.readFileSync(dataPath, "utf8"));

  const user = users.find((user) => user.username === username);

  if (!user) {
    return res.status(404).json({ message: "用户名不存在" });
  }

  bcrypt.compare(password, user.password, (err, result) => {
    if (result) {
      // 密码匹配，创建Token
      const token = jwt.sign(
        { id: user.id, username: user.username },
        SECRET_KEY,
        { expiresIn: "1h" }
      );
      // 返回Token和用户信息（不包含密码）
      res.json({
        message: "登录成功",
        token,
        user: { ...user, password: undefined },
      });
    } else {
      res.status(401).json({ message: "密码错误" });
    }
  });
});
app.post("/api/avatar", (req, res) => {
  const { username, url } = req.body;
  console.log(username, url);
  if (url.startsWith("data:image")) {
    const base64Data = url.replace(/^data:image\/\w+;base64,/, "");
    const buffer = Buffer.from(base64Data, "base64");
    const imgPath = path.join("public", "images", `${username}_avatar.jpg`);

    // 检查是否存在同名文件，如果存在，则删除
    if (fs.existsSync(imgPath)) {
      fs.unlinkSync(imgPath);
      console.log(`已删除旧文件：${imgPath}`);
    } else {
      console.log(`不存在旧文件：${imgPath}`);
    }
    // 写入新的图片文件
    fs.writeFileSync(imgPath, buffer);
    console.log("文件写入成功");
  }
  const users = JSON.parse(fs.readFileSync(dataPath, "utf8"));
  const userToUpdate = users.find((user) => user.username === username);
  if (userToUpdate) {
    // 更新用户的头像路径
    userToUpdate.avatar = path
      .join("images", `${username}_avatar.jpg`)
      .replace(/\\/g, "/");

    // 将更新后的用户列表写回到 JSON 文件中
    fs.writeFileSync(dataPath, JSON.stringify(users, null, 2), "utf8");
    console.log("用户头像路径更新成功！");
    res.json({ success: true, user: userToUpdate });
  } else {
    console.log("未找到需要更新头像的用户！");
  }
});

// 微信分享后端接口实现
// 接口配置信息测试
app.post("/api/wxJssdk", async (req, res) => {
  const grant_type = "client_credential";
  // 测试号
  const appid = "wx7038d3636b5797ed";
  const secret = "bd3dbda5b59c8f6c1057fb9edd163acd";

  try {
    const response1 = await axios.get(
      "https://api.weixin.qq.com/cgi-bin/token?grant_type=" +
        grant_type +
        "&appid=" +
        appid +
        "&secret=" +
        secret
    );
    const access_token = response1.data.access_token;
    const response2 = await axios.get(
      "https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=" +
        access_token +
        "&type=jsapi"
    );
    const jsapi_ticket = response2.data.ticket;

    const nonce_str = "123456"; // 随机字符串
    const timestamp = new Date().getTime(); // 时间戳
    const url = req.query.url; // 请求的 URL

    // 构造待加密字符串
    const str = `jsapi_ticket=${jsapi_ticket}&noncestr=${nonce_str}&timestamp=${timestamp}&url=${url}`;

    // 使用 sha1 加密
    const signature = sha1(str);

    res.send({
      appId: appid,
      timestamp: timestamp,
      nonceStr: nonce_str,
      signature: signature,
    });
  } catch (err) {
    console.error("Error fetching data:", err.message);
    res.status(500).send("Internal Server Error");
  }
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
