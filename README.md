Patches to enhance EFB functionality
==========================
[![PyPI release](https://img.shields.io/pypi/v/efb-patch-middleware.svg)](https://pypi.org/project/efb-patch-middleware/)
[![Downloads](https://pepy.tech/badge/efb-patch-middleware/month)](https://pypi.org/project/efb-patch-middleware/)

### Main Function

- Telegram administrator can send messages
- Automatically mark read on WeChat (**received messages on telegram** will mark read)
- In a group, only one note is displayed when the note has the same name (or one is included by the other)
- ~~/update_info command adds WeChat group member information to telegram group description~~ (supported)
- Establish a database to save the tg group and WeChat chat/group name mapping. When there is no binding, try to find a group with the same name and automatically bind (two-way)
- Delete unnecessary messages when receiving pictures, videos, files, for example: sent a picture. <sup>[1]</sup>
- Applet sharing adds "Applet:" title prefix to distinguish regular links
- Use <code>rm`</code> to reply to the message sent by yourself (telegram message cannot be edited )

### compatible version

```text
EFB 2.1.0
ETM 2.2.4
EWS 2.0.4
```

### Usage

The `/update_info` command will bind the current group to the WeChat chat one-to-one correspondence  
The `/relate_group` command binds the WeChat group to the current telegram group, and can be associated with multiple WeChat chats; repeated use will clear the previous binding relationship  
The `/release_group` command will delete all WeChat sessions bound to the telegram group  

Add the following configuration under `blueset.telegram/config.yaml`, and send the public account message to the `-12334557` group (view the id through the `/info` command)

```yaml
tg_mp: -12334557 # telegram group id
```

### Config

file path `~/.ehforwarderbot/profiles/default/patch.PatchMiddleware/config.yaml`  

```yaml
auto_mark_as_read: True # auto mark as read in wechat phone client
remove_emoji_in_title: True # wouldn't remove emoji in telegram group title if this is set False
strikethrough_recall_msg: True # strikethrough instead of replying to a recall message
```

### Installation

```bash
pip3 install efb-patch-middleware
```

`~/.ehforwarderbot/profiles/default/config.yaml` file add to configuration enable middleware

```yaml
master_channel: blueset.telegram
slave_channels:
- blueset.wechat
middlewares:
- patch.PatchMiddleware
```

### Data Backup

Data is saved under `.ehforwarderbot/profiles/default/patch.PatchMiddleware/tg_group.db`

### Difference between `/update_info` and `/relate_group`  

`/update_info` is the original command of efb, which will update the WeChat session avatar and name to the tg group, and only supports binding a WeChat session. Now this command has been extended to synchronize the WeChat session name with the tg group ID. Binding one-to-one correspondence. After the link fails, replace the original failed link with the latest one

`/relate_group` is a new command for middleware. The application scenario is that tg group is used when binding multiple WeChat sessions. (Usually when multiple public accounts are bound to a tg group.) **A message needs to be answered when used**

> [1]: Forward picture-type messages received by WeChat end usually with author name, remove picture title when forwarding such messages
