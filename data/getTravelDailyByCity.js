const fs = require("fs");
const request = require("request");

const CityList = [
  { cityName: "北京", cityID: "1", isDomesticCity: "1" },
  { cityName: "上海", cityID: "2", isDomesticCity: "1" },
  { cityName: "广州", cityID: "152", isDomesticCity: "1" },
  { cityName: "成都", cityID: "104", isDomesticCity: "1" },
];

function sendRequest(cityInf, idx) {
  return new Promise((resolve, reject) => {
    request(
      {
        uri: "https://m.ctrip.com/restapi/soa2/13012/getWaterflowInfo?_fxpcqlniredt=09031131312253917969",
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
          componentType: "h5",
          sourceid: "destination",
          appId: "99999999",
          tripStatus: "0",
          globalName: cityInf.cityName,
          globalID: cityInf.cityID,
          callback: '{"prodNumber":"300"}',
          isDomesticCity: "1",
          source: "destination",
          tabType: "TOPIC",
          tabId: "mix",
          deviceInfo: {
            screenWidth: 375,
            screenHeight: 667,
            deviceType: "PHONE",
            type: "H5",
            os: "ios",
            osv: "16.6",
          },
          globalInfo: {
            type: 6,
            id: cityInf.cityID,
            name: cityInf.cityName,
            geoType: "gs_district",
          },
          hotelInfo: {},
          pageInfo: { size: 10, index: idx },
          coordinate: {},
          conf: {},
          ext: {},
          selectedFastFilters: [],
          selectedTabs: [],
          head: {
            cid: "09031131312253917969",
            ctok: "",
            cver: "1.0",
            lang: "01",
            sid: "8888",
            syscode: "09",
            auth: "",
            xsid: "",
            extension: [],
          },
        },
      },
      (error, response, body) => {
        if (error) reject(error);
        else {
          // 返回当前城市用户游记数据
          resolve(body.data.items);
        }
      }
    );
  });
}

let responseData = [];
async function fetchAllData() {
  for (let i = 0; i < CityList.length; i++) {
    responseData = [];
    for (let pageidx = 1; pageidx < 3; pageidx++) {
      try {
        // 等待sendRequest解析完成，然后将数据push到responseData
        const data = await sendRequest(CityList[i], pageidx);
        data.forEach((info) => {
          responseData.push(JSON.parse(info));
        });
      } catch (error) {
        console.error("请求发生错误：", error);
      }
    }
    // 现在responseData包含了所有数据，可以将其写入文件
    fs.writeFileSync(
      `original_data/${CityList[i].cityName}.json`,
      JSON.stringify(responseData)
    );
  }
}

fetchAllData();
