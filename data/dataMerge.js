const fs = require("fs");
const request = require("request");

// 对四个城市的旅游日记进行打乱。
function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1)); // 随机选择一个索引
        [array[i], array[j]] = [array[j], array[i]]; // 交换元素
    }
    return array;
}

const CityList = [
    { cityName: "上海", cityID: "2", isDomesticCity: "1" },
  { cityName: "北京", cityID: "1", isDomesticCity: "1" },
  { cityName: "广州", cityID: "152", isDomesticCity: "1" },
  { cityName: "杭州", cityID: "14", isDomesticCity: "1" },
  { cityName: "成都", cityID: "104", isDomesticCity: "1" },
  { cityName: "南京", cityID: "9", isDomesticCity: "1" },
  { cityName: "西安", cityID: "7", isDomesticCity: "1" },
  { cityName: "重庆", cityID: "158", isDomesticCity: "1" },
  { cityName: "深圳", cityID: "26", isDomesticCity: "1" },
  ];

// 合并四个城市的旅游日记
let finally_path = './travel_data/'
let total_data = []
for (let i = 0; i < CityList.length; i++) {
    const data = fs.readFileSync(finally_path+`${CityList[i].cityName}.json`, "utf8");
    const jsondata = JSON.parse(data);
    for(let item of jsondata) {
        total_data.push(item);
    }
}

shuffleArray(total_data);

fs.writeFileSync( "totalTravelData.json",  JSON.stringify(total_data));

