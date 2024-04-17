const fs = require("fs");
const request = require("request");

const Topics = [
  { Name: "春日赏花图鉴", id: "574538" },
  { Name: "小众免费打卡地推荐", id: "64672" },
  { Name: "春天玩点花的", id: "641810" },
  { Name: "捕捉城市人文", id: "104539" },
  { Name: "发现旅途的色彩", id: "80694" },
  { Name: "值得去的古镇古村", id: "12773" },
  { Name: "春天玩点花的", id: "641810" },
  { Name: "溜娃好去处", id: "59350" },
];

// 找主题描述和文本;
function getTopicInfo(topicID) {
  return new Promise((resolve, reject) => {
    request(
      {
        uri: `https://m.ctrip.com/restapi/soa2/14045/json/getTopicListByIds?_fxpcqlniredt=09031131312253917969&x-traceID=09031131312253917969-1712229835129-7898732`,
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
          ids: [topicID],
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
          // 返回当前topic游记数据
          resolve(body.topics);
        }
      }
    );
  });
}

// 找主题数据
function getDataOfTopic(topicID, idx) {
  return new Promise((resolve, reject) => {
    request(
      {
        uri: `https://m.ctrip.com/restapi/soa2/14045/json/searchGroupArticleList?_fxpcqlniredt=09031131312253917969&x-traceID=09031131312253917969-1712218944682-5823426`,
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
          groupChannelCode: "total",
          productTypes: [5],
          levels: [1, 2, 3, 4],
          appendPoiExt: true,
          pagePara: {
            pageIndex: idx,
            pageSize: 10,
            sortType: 52,
            sortDirection: 0,
          },
          imageCutType: 1,
          topicIds: [topicID],
          topTopicGroupArticle: true,
          showallimage: true,
          pageSourceType: "topic",
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
          // 返回当前topic游记数据
          resolve(body.resultList);
        }
      }
    );
  });
}

let responseData = [];
async function fetchAllData() {
  for (let i = 0; i < Topics.length; i++) {
    responseData = { topic: {}, data: [] };
    var number = 0;
    const tp = await getTopicInfo(Topics[i].id);
    const topic = tp[0];
    // 清洗主题数据
    responseData["topic"] = {
      topicId: topic.topicId,
      topicName: topic.topicName,
      remark: topic.remark,
      image: {
        url: topic.image.dynamicUrl,
        width: topic.image.width,
        height: topic.image.height,
      },
      heat: topic.heat,
      heatText: topic.heatText,
      hotValue: topic.hotValue,
    };
    for (let pageidx = 1; ; pageidx++) {
      if (number >= 30) break;
      try {
        // 等待sendRequest解析完成，然后将数据push到responseData
        const data = await getDataOfTopic(Topics[i].id, pageidx);
        data.forEach((item) => {
          // const item = JSON.parse(info);
          // 消除带视频的数据
          if (item.hasVideo === false) {
            // 清洗游记数据
            responseData["data"].push({
              id: item.articleId,
              title: item.articleTitle,
              coverImg: item.images[0].dynamicUrl,
              user: {
                icon: item.author.coverImage.dynamicUrl,
                nickName: item.author.nickName,
                interactionText: item.readCount,
                likeCount:item.likeCount,
                commentCount: item.commentCount,
                shareCount: item.shareCount,
                interactionIcon: "https://images4.c-ctrip.com/target/0zc3v120008xuwygkC3B0.png",
              },
              city: item.ipLocatedName,
              isChecked: 1,
              checkReason: "",
              districtPoiCollect: {
                poiNames: item.pois.filter((value)=> value.poiName).map((value)=> value.poiName),
                districtNames: item.pois.filter((value)=> value.districtName).map((value)=> value.districtName),
              },
              images: item.images.map((value)=> {return {id: value.id, url: value.dynamicUrl, width: value.width, height: value.height}}),
              content: item.content,
              publishTime: item.publishTime,
              firstPublishTime: item.firstPublishTime,
              publishDisplayTime: item.publishTimeDisplay,
              shootTime: item.shootTime,
              shootDisplayTime: item.shootTimeDisplay,
            });
            number++;
          }
        });
      } catch (error) {
        console.error("请求发生错误：", error);
      }
    }
    // 现在responseData包含了所有数据，可以将其写入文件
    fs.writeFileSync(
      `topic_data/${Topics[i].id}.json`,
      JSON.stringify(responseData)
    );
  }
}

fetchAllData();

