const { Console } = require("console");
const fs = require("fs");
const request = require("request");


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


let data_base = './travel_data/'
let save_base = './CityTravelData/'
for (let i = 0; i < CityList.length; i++){
    const data = fs.readFileSync(data_base+`${CityList[i].cityName}.json`, "utf8");
    const jsondata = JSON.parse(data);
    let new_jsondata = [];
    for(let item of jsondata) {
        const content = item.detail.summary.content;
        const ctagRegex = /<ctag.*?>(.*?)<\/ctag>/g;
        const pioRegex = /<poi.*?>(.*?)<\/poi>/g;
        const cleanedText = content.replace(ctagRegex,'$1').replace(pioRegex,'$1');
        new_jsondata.push({
            id: parseInt(item.id),
            title: item.title,
            coverImg: item.img_Intrinsic,
            user: {
                icon: item.user.icon,
                nickName: item.user.nickname,
                interactionText: parseInt(item.user.interactionText),
                interactionIcon: item.user.interactionIcon
            },
            city: item.traffic.city,
            isChecked: item.isChecked,
            checkReason: "",
            districtPoiCollect: {
                poiNames: item.detail.districtPoiCollect.poiNames,
                districtNames: item.detail.districtPoiCollect.districtNames
            },
            images: item.detail.images.map((value)=>{
                return {id: value.id, url: value.url.replace(/.jpg/, '_W_800_0_Q90.jpg'), 
                    width: value.width, height: value.height, needAuth: value.needAuth, pois: value.pois}
            }),
            content: cleanedText,
            publishTime: item.detail.summary.publishTime,
            firstPublishTime: item.detail.summary.firstPublishTime,
            publishDisplayTime: item.detail.summary.publishDisplayTime,
            shootTime: item.detail.summary.shootTime,
            shootDisplayTime: item.detail.summary.shootDisplayTime,
        })
    }

    fs.writeFileSync( save_base+`${CityList[i].cityID}.json`,  JSON.stringify(new_jsondata));
}