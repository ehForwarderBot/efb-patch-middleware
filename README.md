
### 主要功能

- telegram管理员可发消息
- 微信端自动标记已读（在telegram**接收到**的消息都会标记已读）
- 群组内，备注与名称相同（或者一个被另一个包含）时，只展示一个
- ~~/update_info 命令将微信群成员信息添加到telegram群描述~~（已支持）
- 建立数据库保存tg群组与微信聊天/群组名称的映射，没有绑定时，尝试查找相同名称的群组自动绑定
- 删除接收图片、视频、文件时，不必要的消息，比如：sent a picture. <sup>[1]</sup>
- 小程序分享添加“小程序：”标题前缀来区分常规链接
- 用<code>rm`</code>回复自己发送的消息来撤回（不能编辑的telegram消息）

### 兼容版本

```text
EFB 2.0.0b22
ETM 2.0.0b30
EWS 2.0.0a32
```

### 使用  

`/update_info`命令会将当前群组与微信chat绑定一一对应关系  
`/relate_group`命令会将微信群组绑定到当前telegram群组，可以关联多个微信chat；重复使用会清除之前的绑定关系
`/release_group`命令会删除telegram群组绑定的所有微信会话

`blueset.telegram/config.yaml`下添加以下配置，会将公众号消息发送到`-12334557`群组（通过`/info`命令查看id）

```yaml
tg_mp: -12334557  # telegram 群id
```

### 安装

`patch.py`拷贝到`~/.ehforwarderbot/modules/`目录  

`~/.ehforwarderbot/profiles/default/config.yaml`文件添加配置启用中间件

```yaml
master_channel: blueset.telegram
slave_channels:
- blueset.wechat
middlewares:
- patch.PatchMiddleware
```

### 数据备份

数据保存在.ehforwarderbot/profiles/default/patch.PatchMiddleware/tg_group.db文件下

### `/update_info`与`/relate_group`的区别

`/update_info`是efb原有的指令，会将微信会话头像，名称更新到tg群组，且只支持绑定一个微信会话，现在将这个命令做了扩展，同步将微信会话名称跟tg群ID绑定一一对应关系。在link失效后，将原来的失效link替换成最新的

`/relate_group`是中间件新增的命令，应用场景是tg群在绑定多个微信会话时使用。（通常是多个公众号绑定到一个tg群时。）**使用时需要回复一条消息**

> [1] : 转发微信端接收到的图片类消息通常带有作者名称，转发此类消息时移除图片标题
