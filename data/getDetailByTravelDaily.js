const fs = require("fs");
const request = require("request");

const CityList = [
  { cityName: "北京", cityID: "1", isDomesticCity: "1" },
  { cityName: "上海", cityID: "2", isDomesticCity: "1" },
  { cityName: "广州", cityID: "152", isDomesticCity: "1" },
  { cityName: "成都", cityID: "104", isDomesticCity: "1" },
];

function sendRequest(articleId) {
  return new Promise((resolve, reject) => {
    request(
      {
        uri: "https://m.ctrip.com/restapi/soa2/16189/json/articleDetail?_fxpcqlniredt=09031131312253917969",
        method: "POST",
        headers: {
          accept: "*/*",
          "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
          "cache-control": "no-cache",
          "content-type": "application/json",
          cookieorigin: "https://m.ctrip.com",
          pragma: "no-cache",
          "sec-fetch-dest": "empty",
          "sec-fetch-mode": "cors",
          "sec-fetch-site": "same-origin",
        },
        json: {
            action: "get",
            articleId: articleId,
            needParts: [
              "CONTENT",
              "AUTHOR",
              "FOLLOW_STATUS",
              "STAT_FOLLOW_COUNT",
              "SHARE_INFO",
              "STATS",
              "ORDER_LOCK",
              "GRUPPE",
              "POI",
              "ALBUM",
              "RANK",
              "ADVERTISE_CUSTOMER",
              "TOPIC",
              "LIKE",
              "LOGIN_USER",
              "IMAGE_POI",
              "COMMENT",
              "LOGIN_USER",
              "TRAVEL",
              "ATTENTION_TIPS",
              "EVENT_RANK",
              "DISTRICT_POI_COLLECT",
            ],
            sharer: { clientAuth: "", token: "" },
            head: {
              cid: "09031131312253917969",
              ctok: "",
              cver: "1.0",
              lang: "01",
              sid: "8888",
              syscode: "09",
              auth: "",
              xsid: "",
              extension: [
                { name: "tecode", value: "h5" },
                { name: "source", value: "web" },
                { name: "technology", value: "H5" },
                { name: "os", value: "IOS" },
                { name: "application", value: "" },
              ],
            },
          },
      },
      (error, response, body) => {
        if (error) reject(error);
        else {
          // 返回当前城市用户游记数据
          resolve(body.article);
        }
      }
    );
  });
}


let filter_path = './filter_data/';
async function fetchAllData() {
  for (let i = 0; i < CityList.length; i++) {
    const data = fs.readFileSync(filter_path+`${CityList[i].cityName}.json`, "utf8");
    const jsondata = JSON.parse(data);
    let new_jsondata = [];
    for(let item of jsondata){
        const travel_detail = await sendRequest(item.id);
        new_jsondata.push({
            ...item,
            detail:{
                districtPoiCollect: travel_detail.districtPoiCollect,
                images: travel_detail.images,
                summary: travel_detail.summary
            }
        })
    }
    // 现在responseData包含了所有数据，可以将其写入文件
    fs.writeFileSync(
      `travel_data/${CityList[i].cityName}.json`,
      JSON.stringify(new_jsondata)
    );
  }
}

fetchAllData();
