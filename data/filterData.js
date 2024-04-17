const request = require("request");
const fs = require("fs");

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

const origin_path = './original_data/'
const filter_path = './filter_data/'


for (let i = 0; i < CityList.length; i++) {
    const data = fs.readFileSync(origin_path+`${CityList[i].cityName}.json`, "utf8");
    const jsondata = JSON.parse(data);
    const new_jsondata = jsondata.map((item) => {
        // 过滤掉广告和有视频的用户数据，只保留图片用户数据
        if (item.hasOwnProperty("clientAuth") && item.ext.hasvideo==="0") {
            // 清洗数据删除某些字段,和添加某些字段
            delete item.ext;
            delete item.itag;
            delete item.type;
            const img_url = item.img.img1.url;
            const  add_idx = img_url.length - 4;
            const img_Intrinsic = img_url.slice(0,add_idx) + '_D_450_600_R5_Q80' + img_url.slice(add_idx);  // 用于瀑布流图片展示
            return {
                ...item,
                img_Intrinsic: img_Intrinsic,
                isChecked: 1 // 添加审核字段，0表示未审核，1表示审核通过，2表示审核未通过
            };
        }
        else return null;
    })
    const save_jsondata = new_jsondata.filter(item => item !== null);
    fs.writeFileSync(
        filter_path+ `${CityList[i].cityName}.json`,
        JSON.stringify(save_jsondata)
      );
}


