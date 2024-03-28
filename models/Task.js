const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
  taskNumber: {
    type: String,
    required: true
  },
  details: {
    type: String,
    required: true
  },
  time: {
    type: Date,
    required: true
  },
  completed: {
    type: Boolean,
    default: false
  }
});

const Task = mongoose.model('Task', taskSchema);

module.exports = Task;
