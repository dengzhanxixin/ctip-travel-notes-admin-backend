const { Console } = require("console");
const fs = require("fs");
const request = require("request");

const data = fs.readFileSync(`totalTravelData.json`, "utf8");
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
        images: item.detail.images,
        content: cleanedText,
        publishTime: item.detail.summary.publishTime,
        firstPublishTime: item.detail.summary.firstPublishTime,
        publishDisplayTime: item.detail.summary.publishDisplayTime,
        shootTime: item.detail.summary.shootTime,
        shootDisplayTime: item.detail.summary.shootDisplayTime,
    })
}

fs.writeFileSync( "TravelData.json",  JSON.stringify(new_jsondata));