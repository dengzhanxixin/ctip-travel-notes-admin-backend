const fs = require("fs");
const path = require("path");

// 修改这里的路径，使其相对于 index.js 或其他调用文件的位置
const getFilePath = (fileName) => path.join(__dirname, "data", fileName);

const readDataFromFile = (fileName) => {
  try {
    const filePath = getFilePath(fileName);
    const data = fs.readFileSync(filePath, "utf8");
    return JSON.parse(data);
  } catch (error) {
    console.error(`读取${fileName}时出错:`, error);
    return [];
  }
};

const writeDataToFile = (fileName, data) => {
  try {
    const filePath = getFilePath(fileName);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
  } catch (error) {
    console.error(`写入${fileName}时出错:`, error);
  }
};

module.exports = { readDataFromFile, writeDataToFile };
