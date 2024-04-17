# 携程后端数据爬取
基于`request`和`fs`爬取了携程 app 上北京、上海、广州和成都四个城市的用户旅游日记数据

## 数据文件说明
```bash
/
├── original_data              #爬取的原始数据，没有过滤掉广告和某些不需要的字段
├── filter_data                #过滤掉了广告和视频，删除了某些字段，添加了审核isChecked字段
├── travel_data                #在filter_data基础上爬取了每个游记详情字段detail，
├── totalTravelData.json       #在travel_data基础上将四个城市数据打乱合并

```

**如果要使用数据，请使用totalTravelData.json中的数据**

## totalTravelData中各字段含义
- "id": 游记序号（唯一）
- "title": 游记标题
- "img": 瀑布流展示图片，三张相同
- "user": 用户信息
- "isChecked": 审核是否通过，0：未审核；1：审核通过；2.审核未通过
- "detail": 游记详情
    - "districtPoiCollect": 地标点
    - "images": 游记图片
    - "summary":游记信息
        - "content": 游记文本
        - "publishDisplayTime": 发布时间

注意：还有些字段还未用到，如果后续扩展功能可以使用，可以参考携程h5的页面



