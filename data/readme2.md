# 清洗数据说明
对数据进行了重新清洗，以便后续使用。注意：某些字段数据类型可能发生改变，需要大家对自己代码进行校验


## TravelData中各字段含义
- "id": 游记序号（唯一）, 由string转为了number
- "title": 游记标题
- "coverImg": 瀑布流展示图片
- "user": 用户信息，包含头像、名称、游记浏览数和浏览icon图标
- "isChecked": 审核是否通过，0：未审核；1：审核通过；2.审核未通过
- "checkReason": 审核未通过时的理由
- "districtPoiCollect": 游记内容的一些标签
- "images": 游记详情中展示的图片
- "content": 游记详情文字
- "publishTime": 发布时间
- "firstPublishTime": 第一次发布时间
- "publishDisplayTime": 展示的发布时间
- "shootTime": 拍摄时间
- "shootDisplayTime": 展示的拍摄时间

注意：还有些字段还未用到，如果后续扩展功能可以使用，可以参考携程h5的页面



