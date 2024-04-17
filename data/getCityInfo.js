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

function sendRequest(cityInf) {
  return new Promise((resolve, reject) => {
    request(
      {
        uri: "https://m.ctrip.com/restapi/soa2/17916/json/invokeOnDemand?_fxpcqlniredt=09031131312253917969&x-traceID=09031131312253917969-1712284775864-362984",
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
          data: `{"districtId":${cityInf.cityID},"platform":"09","location":{"latitude":"","longitude":""}}`,
          serviceName: "DestinationCoreService.getDestPage",
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
          resolve(body.data);
        }
      }
    );
  });
}

let responseData = [];
async function fetchAllData() {
  for (let i = 0; i < CityList.length; i++) {
    try {
      // 等待sendRequest解析完成，然后将数据push到responseData
      const data = await sendRequest(CityList[i]);
      const jsondata = JSON.parse(data);

      responseData.push({
        cityName: jsondata.head.district.name,
        cityID: jsondata.head.district.districtId,
        eName: jsondata.head.district.eName,
        photoCount: jsondata.head.photoCount,
        coverImage: jsondata.shareInfo.coverImage,
      });
    } catch (error) {
      console.error("请求发生错误：", error);
    }
  }
  // 现在responseData包含了所有数据，可以将其写入文件
  fs.writeFileSync(
    `CityTravelData/cityInfo.json`,
    JSON.stringify(responseData)
  );
}

fetchAllData();
