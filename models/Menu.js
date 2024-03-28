const mongoose = require("mongoose");

const menuSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  link: {
    type: String,
    required: true,
  },
  // 可以根据需要添加更多字段
});

const Menu = mongoose.model("Menu", menuSchema);

module.exports = Menu;
