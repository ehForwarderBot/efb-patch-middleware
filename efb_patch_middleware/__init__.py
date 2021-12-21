# coding: utf-8
import io
import os
import re
import json
import time
import sched
import logging
import telegram
import itertools
import ffmpeg

import binascii
import functools
import inspect
from types import ModuleType

from PIL import Image
from pathlib import Path
from ruamel.yaml import YAML
from tempfile import NamedTemporaryFile
from xml.etree import ElementTree as ETree
from xml.etree.ElementTree import Element

from typing import Tuple, Optional, List, overload, Callable, Sequence, Any, Dict, IO, Type, Union
from telegram import ChatAction, Update, TelegramError, InputMediaPhoto, InputMediaDocument, InputMediaVideo, ReplyMarkup, Contact
from telegram.ext import CallbackContext, Filters, MessageHandler, CommandHandler
from telegram.error import BadRequest
from telegram.utils.helpers import escape_markdown

from ehforwarderbot import Middleware, Message, Status, coordinator, Channel, utils as efb_utils
from ehforwarderbot.constants import MsgType
from ehforwarderbot.chat import ChatNotificationState, SelfChatMember, GroupChat, PrivateChat, SystemChat, Chat, SystemChatMember
from ehforwarderbot.exceptions import EFBChatNotFound, EFBOperationNotSupported, EFBMessageTypeNotSupported, \
    EFBMessageNotFound, EFBMessageError, EFBException
from ehforwarderbot.types import ModuleID, ChatID, MessageID
from ehforwarderbot.message import LocationAttribute
from ehforwarderbot.status import ChatUpdates, MemberUpdates, MessageRemoval, MessageReactionsUpdate

from efb_telegram_master import utils
from efb_telegram_master.utils import TelegramMessageID, TelegramChatID, EFBChannelChatIDStr, TgChatMsgIDStr
from efb_telegram_master.chat import convert_chat, ETMGroupChat
from efb_telegram_master.constants import Emoji
from efb_telegram_master.message import ETMMsg
from efb_telegram_master.msg_type import TGMsgType, get_msg_type
from efb_telegram_master.chat_destination_cache import ChatDestinationCache
from efb_telegram_master.db import SlaveChatInfo


from efb_wechat_slave import utils as ews_utils
from efb_wechat_slave.vendor import wxpy
from efb_wechat_slave.slave_message import SlaveMessageManager
from efb_wechat_slave.vendor.wxpy import ResponseError
from efb_wechat_slave.vendor.wxpy.api.consts import SYSTEM
from efb_wechat_slave.vendor.wxpy.api.bot import Bot as WXPYBOT
from efb_wechat_slave.vendor.wxpy.utils import start_new_thread

from peewee import Model, TextField, SqliteDatabase, DoesNotExist, fn, BlobField, \
    OperationalError

from .__version__ import __version__ as version

database = SqliteDatabase(None)

OldMsgID = Tuple[TelegramChatID, TelegramMessageID]

schedule = sched.scheduler(time.time, time.sleep)

DALAY_MARK_AS_READ = 10

GIF_MAX_FILE_SIZE = 2 ** 20

patch_result = []

class BaseModel(Model):
    class Meta:
        database = database

class TgGroups(BaseModel):
    master_id = TextField()
    master_name = TextField()
    multi_slaves = TextField(null=True)

class DatabaseManager:
    logger = logging.getLogger(__name__)

    def __init__(self, middleware_id):
        base_path = efb_utils.get_data_path(middleware_id)

        database.init(str(base_path / 'tg_group.db'))
        database.connect()

        self.tg_cache: ChatDestinationCache = ChatDestinationCache('enabled')

        if not TgGroups.table_exists():
            self._create()

    @staticmethod
    def _create():
        """
        Initializing tables.
        """
        database.execute_sql("PRAGMA journal_mode = OFF")
        database.create_tables([TgGroups])

    def add_tg_groups(self, master_id, master_name, multi_slaves=None):
        """
        Add chat associations.
        One Master channel with one/many Slave channel.

        Args:
            master_id (str): Telegram group id
            master_name (str): Slave channel name
            multi_slaves: Allow linking to multiple slave channels.
        """
        if not multi_slaves:
            self.remove_tg_groups(master_id=master_id)
        self.remove_tg_groups(master_name=master_name)

        return TgGroups.create(master_id=master_id, master_name=master_name, multi_slaves=multi_slaves)

    @staticmethod
    def remove_tg_groups(master_id=None, master_name=None):
        """
        Remove chat associations.
        Only one parameter is to be provided.

        Args:
            master_id (str): Master chat UID ("%(chat_id)s")
            master_name (str): Slave channel name
        """
        if master_id is None and master_name is None:
            return 0

        try:
            if master_name:
                return TgGroups.delete().where(TgGroups.master_name == master_name).execute()

            return TgGroups.delete().where(TgGroups.master_id == master_id).execute()
        except DoesNotExist:
            return 0

    def get_tg_groups(self, master_name):
        """
        Get chat association information.
        Only one parameter is to be provided.

        Args:
            master_name (str): Slave channel name

        Returns:
            The association information.
        """
        if self.tg_cache.get(master_name):
            return None
        try:
            return TgGroups.select().where(TgGroups.master_name == master_name).first()
        except DoesNotExist:
            # 缓存不存在结果，避免持续查db
            self.tg_cache.set(master_name, True, 300)
            return None

    def get_wx_groups(self, master_id):
        """
        Get chat association information.
        Only one parameter is to be provided.

        Args:
            master_id (str): Telegram group id

        Returns:
            The association information.
        """
        if self.tg_cache.get(master_id):
            return None
        try:
            return TgGroups.select().where(TgGroups.master_id == master_id, TgGroups.multi_slaves.is_null(True)).first()
        except DoesNotExist:
            # 缓存不存在结果，避免持续查db
            self.tg_cache.set(master_id, True, 300)
            return None

    def update_tg_groups(self, master_id, master_name):
        """
            更新wx chat标题
        """
        try:
            masters = TgGroups.select(TgGroups.master_name).where(TgGroups.master_id == master_id)
            if len(masters) > 0:
                TgGroups.update(master_name = master_name).where(TgGroups.master_id == master_id).execute()
                self.logger.debug("update wx chat title from [%s] to [%s]", masters[0].master_name, master_name)
                return True

        except DoesNotExist:
            return False

"""
tg管理员可发消息
微信端自动标记已读
群组内，备注与名称相同时，只展示一个
/update_info 命令将微信群成员信息添加到telegram群描述
建立数据库保存tg群组与微信聊天/群组名称的映射，没有绑定时，尝试查找相同名称的群组自动绑定
删除接收图片、视频、文件时，不必要的消息，比如：sent a picture.
"""
class PatchMiddleware(Middleware):
    """
    EFB Middleware - PatchMiddleware
    """

    middleware_id = "patch.PatchMiddleware"
    middleware_name = "Patch Middleware"
    __version__: str = version

    logger: logging.Logger = logging.getLogger("plugins.%s" % middleware_id)

    def __init__(self, instance_id=None):
        super().__init__()
        self.tgdb: DatabaseManager = DatabaseManager(self.middleware_id)
        self.load_config()

        if hasattr(coordinator, "master") and isinstance(coordinator.master, Channel):
            self.channel = coordinator.master
            self.updater = self.channel.bot_manager.updater
            self.dispatcher = self.channel.bot_manager.dispatcher
            self.chat_binding = self.channel.chat_binding
            self.master_messages = self.channel.master_messages
            self.slave_messages = self.channel.slave_messages
            self.chat_manager = self.channel.chat_manager
            self.channel_id = self.channel.channel_id


            self.bot = self.channel.bot_manager
            self.db = self.channel.db
            self._ = self.channel._
            self.ngettext = self.channel.ngettext
            self.MAX_LEN_CHAT_DESC = self.chat_binding.MAX_LEN_CHAT_DESC
            self.MAX_LEN_CHAT_TITLE = self.chat_binding.MAX_LEN_CHAT_TITLE
            self.TELEGRAM_MIN_PROFILE_PICTURE_SIZE = self.chat_binding.TELEGRAM_MIN_PROFILE_PICTURE_SIZE
            self.truncate_ellipsis = self.chat_binding.truncate_ellipsis

            self.IMG_MIN_SIZE = self.slave_messages.IMG_MIN_SIZE
            self.IMG_MAX_SIZE = self.slave_messages.IMG_MAX_SIZE
            self.IMG_SIZE_RATIO = self.slave_messages.IMG_SIZE_RATIO
            self.IMG_SIZE_MAX_RATIO = self.slave_messages.IMG_SIZE_MAX_RATIO

            self.chat_dest_cache = self.slave_messages.chat_dest_cache
            self.check_file_size = self.slave_messages.check_file_size
            self.html_substitutions = self.slave_messages.html_substitutions

            self.get_singly_linked_chat_id_str = self.master_messages.get_singly_linked_chat_id_str
            self._send_cached_chat_warning = self.master_messages._send_cached_chat_warning
            self._check_file_download = self.master_messages._check_file_download
            self.attach_target_message = self.master_messages.attach_target_message
            self.TYPE_DICT = self.master_messages.TYPE_DICT

            self.db.get_slave_chat_contact_alias = self.get_slave_chat_contact_alias
            self.etm_master_messages_patch()
            self.etm_slave_messages_patch()
            self.etm_chat_binding_patch()

        if hasattr(coordinator, "slaves") and coordinator.slaves['blueset.wechat']:
            self.channel_ews = coordinator.slaves['blueset.wechat']
            self.chats = self.channel_ews.chats
            self.flag = self.channel_ews.flag
            self.user_auth_chat = self.channel_ews.user_auth_chat

            self.registered = self.channel_ews.bot.registered
            self._bot_send_msg = self.channel_ews._bot_send_msg
            self._bot_send_file = self.channel_ews._bot_send_file
            self._bot_send_image = self.channel_ews._bot_send_image
            self._bot_send_video = self.channel_ews._bot_send_video
            self.MAX_FILE_SIZE = self.channel_ews.MAX_FILE_SIZE
            self.MEDIA_MSG_TYPES = self.channel_ews.MEDIA_MSG_TYPES

            self.wechat_unsupported_msg = self.channel_ews.slave_message.wechat_unsupported_msg
            self.wechat_shared_image_msg = self.channel_ews.slave_message.wechat_shared_image_msg
            self.wechat_shared_link_msg = self.channel_ews.slave_message.wechat_shared_link_msg
            self.wechat_raw_link_msg = self.channel_ews.slave_message.wechat_raw_link_msg
            self.wechat_text_msg = self.channel_ews.slave_message.wechat_text_msg
            self.get_node_text = self.channel_ews.slave_message.get_node_text
            self.UNSUPPORTED_MSG_PROMPT = self.channel_ews.slave_message.UNSUPPORTED_MSG_PROMPT

            self.ews_set_mark_as_read()
            self.ews_init_patch()
            self.ews_slave_message_patch()

        if len(patch_result) > 0:
            self.logger.log(99, "patch result: [%s]", patch_result)
            self.bot.send_message(self.channel.config['admins'][0], f"中间件[PatchMiddleware {self.__version__}]匹配校验失败，请核查版本")
        # self.logger.log(99, "[%s] init...", self.middleware_name)

    def load_config(self):
        """
        Load configuration from path specified by the framework.

        Configuration file is in YAML format.
        """
        self.AUTO_MARK_AS_READ = True
        self.REMOVE_EMOJI_IN_TITLE = True
        self.STRIKETHROUGH_RECALL_MSG = False
        config_path = efb_utils.get_config_path(self.middleware_id)
        if not config_path.exists():
            return

        with config_path.open() as f:
            data = YAML().load(f)

            self.AUTO_MARK_AS_READ = data.get("auto_mark_as_read", True)
            self.REMOVE_EMOJI_IN_TITLE = data.get("remove_emoji_in_title", True)
            self.STRIKETHROUGH_RECALL_MSG = data.get("strikethrough_recall_msg", False)

    def patch_check(self, f: Callable, crc32: int, patch_base: Union[ModuleType, Type], patch_attr: str):
        """检查并覆盖指定的函数。

        参数：
            f：需要覆盖的新函数（已提供）
            crc32：原函数源码的 CRC32 值（已提供）
            patch_base：需要被覆盖的函数所在类或模块
            patch_attr：需要被覆盖的函数名称

        """
        patch_source = getattr(patch_base, patch_attr)
        base_crc32 = binascii.crc32(inspect.getsource(patch_source).encode())
        if base_crc32 != crc32:
            patch_result.append(f"{patch_attr} CRC32值不匹配，指定的值为 {crc32} ，实际值为 {base_crc32} 。")
            return
        setattr(patch_base, patch_attr, f)

    def patch(self, func, patch_base, patch_attr, crc32: int):
        self.patch_check(func, crc32, patch_base, patch_attr)

    def etm_slave_messages_patch(self):
        self.patch(self.generate_message_template, self.slave_messages, "generate_message_template", 3121137375)
        # self.patch(self.slave_message_image, self.slave_messages, "slave_message_image", 1179016156)
        self.patch(self.get_slave_msg_dest, self.slave_messages, "get_slave_msg_dest", 2284390933)

        if self.STRIKETHROUGH_RECALL_MSG:
            self.patch(self.send_status, self.slave_messages, "send_status", 2710203104)

    def sort_handler(self, handler):
        # 权限校验
        if isinstance(handler, MessageHandler) and handler.callback.__name__ == '<lambda>':
            return 0

        # 指令
        if isinstance(handler, CommandHandler) and handler.command :
            return 1

        return 2

    def etm_master_messages_patch(self):
        self.master_messages.DELETE_FLAG = self.channel.config.get('delete_flag', self.master_messages.DELETE_FLAG)
        self.DELETE_FLAG = self.master_messages.DELETE_FLAG
        self.patch(self.msg, self.master_messages, "msg", 1596462929)
        self.patch(self.process_telegram_message, self.master_messages, "process_telegram_message", 2987607773)

        self.dispatcher.add_handler(CommandHandler('relate_group', self.relate_group))
        self.dispatcher.add_handler(CommandHandler('release_group', self.release_group))

        self.dispatcher.handlers[0].sort(key=self.sort_handler)

        if self.dispatcher.handlers[0] and self.dispatcher.handlers[0][0]:
            self.handler = self.dispatcher.handlers[0][0]

            self.origin_check_update = self.handler.check_update
            self.handler.check_update = self.check_update

    def etm_chat_binding_patch(self):
        if self.dispatcher.handlers[0]:
            for index, item in enumerate(self.dispatcher.handlers[0]):
                if isinstance(item, CommandHandler) and item.command and item.command[0] == 'update_info':
                    item.callback = self.update_group_info

    def check_update(self, update):
        """Determines whether an update should be passed to this handlers :attr:`callback`.

        Args:
            update (:class:`telegram.Update`): Incoming telegram update.

        Returns:
            :obj:`bool`

        """
        if not self.origin_check_update(update):
            return False

        message = update.message or update.edited_message
        if not message:
            if update.channel_post and update.channel_post.reply_to_message:
                return False
            return True
        user = self.updater.bot.getChatMember(message.chat.id, update.effective_user.id, 5)

        # message.text = f"[{message.from_user.username or message.from_user.first_name}]: {message.text}"

        return user.status not in ('administrator', 'creator')

    def ews_set_mark_as_read(self):
        if self.AUTO_MARK_AS_READ:
            self.alive = self.channel_ews.bot.alive
            self.channel_ews.bot.auto_mark_as_read = True
            self.auto_mark_as_read = self.channel_ews.bot.auto_mark_as_read
            self.mark_as_read_cache: ChatDestinationCache = ChatDestinationCache('enabled')
            self.channel_ews.bot._process_message = self._process_message
            WXPYBOT._process_message = self._process_message
            # self.logger.log(99, "set auto_mark_as_read to [%s]", self.channel_ews.bot.auto_mark_as_read)

    def ews_init_patch(self):
        self.channel_ews.send_message = self.send_message

    def ews_slave_message_patch(self):
        config = self.registered.get_config_by_func(self.channel_ews.slave_message.wechat_sharing_msg)
        config.func = self.wechat_sharing_msg
        self.channel_ews.slave_message.wechat_sharing_msg = self.wechat_sharing_msg

    def sent_by_master(self, message: Message) -> bool:
        author = message.author
        return author and author.module_id and author.module_id == 'blueset.telegram'

    def process_message(self, message: Message) -> Optional[Message]:
        """
        Process a message with middleware
        Args:
            message (:obj:`.Message`): Message object to process
        Returns:
            Optional[:obj:`.Message`]: Processed message or None if discarded.
        """

        # if self.sent_by_master(message):
        #     return message

        return message

    # efb_telegram_master/slave_message.py
    def generate_message_template(self, msg: Message, singly_linked: bool) -> str:
        msg_prefix = ""  # For group member name
        if isinstance(msg.chat, GroupChat):
            self.logger.debug("[%s] Message is from a group. Sender: %s", msg.uid, msg.author)
            ### patch modified 👇 ###
            msg_prefix = self.get_display_name(msg.author)

        if singly_linked:
            if msg_prefix:  # if group message
                msg_template = f"{msg_prefix}:"
            else:
                if msg.chat != msg.author:
                    ### patch modified 👇 ###
                    msg_template = f"{self.get_display_name(msg.author)}:"
                else:
                    msg_template = ""
        elif isinstance(msg.chat, PrivateChat):
            emoji_prefix = msg.chat.channel_emoji + Emoji.USER
            ### patch modified 👇 ###
            name_prefix = self.get_display_name(msg.chat)
            if msg.chat.other != msg.author:
                ### patch modified 👇 ###
                name_prefix += f", {self.get_display_name(msg.author)}"
            msg_template = f"{emoji_prefix} #{name_prefix}:"
        elif isinstance(msg.chat, GroupChat):
            emoji_prefix = msg.chat.channel_emoji + Emoji.GROUP
            ### patch modified 👇 ###
            name_prefix = self.get_display_name(msg.chat)
            msg_template = f"{emoji_prefix} {msg_prefix} [#{name_prefix}]:"
        elif isinstance(msg.chat, SystemChat):
            emoji_prefix = msg.chat.channel_emoji + Emoji.SYSTEM
            ### patch modified 👇 ###
            name_prefix = self.get_display_name(msg.chat)
            if msg.chat.other != msg.author:
                name_prefix += f", {self.get_display_name(msg.author)}"
            msg_template = f"{emoji_prefix} #{name_prefix}:"
        else:
            ### patch modified 👇 ###
            msg_template = f"{Emoji.UNKNOWN} {self.get_display_name(msg.author)} ({msg.chat.display_name}):"
        return msg_template

    def get_display_name(self, chat: Chat) -> str:
        # 群成员昵称不存在时获取联系人昵称
        if not chat.alias:
            # self.logger.log(99, 'get display_name %s', chat.__dict__)
            cache = self.chat_manager.get_chat(chat.module_id, chat.uid)
            if not cache:
                # self.logger.log(99, 'no cache: %s', chat.uid)
                chat.alias = self.db.get_slave_chat_contact_alias(chat.uid)
            else:
                # self.logger.log(99, 'get cache %s', cache.__dict__)
                chat.alias = cache.alias

        # self.logger.log(99, "chat: [%s]", chat.__dict__)
        return chat.name if not chat.alias or chat.alias in chat.name \
            else (chat.alias if chat.name in chat.alias else f"{chat.alias} ({chat.name})")

    # efb_telegram_master/slave_message.py
    def slave_message_image(self, msg: Message, tg_dest: TelegramChatID, msg_template: str, reactions: str,
                            old_msg_id: OldMsgID = None,
                            target_msg_id: Optional[TelegramMessageID] = None,
                            reply_markup: Optional[ReplyMarkup] = None,
                            silent: bool = False) -> telegram.Message:
        assert msg.file
        self.bot.send_chat_action(tg_dest, ChatAction.UPLOAD_PHOTO)
        self.logger.debug("[%s] Message is of %s type; Path: %s; MIME: %s", msg.uid, msg.type, msg.path, msg.mime)
        if msg.path:
            self.logger.debug("[%s] Size of %s is %s.", msg.uid, msg.path, os.stat(msg.path).st_size)

        ### patch modified start 👇 ###
        if msg.text:
            text = self.html_substitutions(msg)
        elif msg_template:
            placeholder_flag = self.flag("default_media_prompt")
            if placeholder_flag == "emoji":
                text = "🖼️"
            elif placeholder_flag == "text":
                text = self._("Sent a picture.")
            else:
                text = ""
        else:
            text = ""
        ### patch modified end 👆 ###
        try:
            # Avoid Telegram compression of pictures by sending high definition image messages as files
            # Code adopted from wolfsilver's fork:
            # https://github.com/wolfsilver/efb-telegram-master/blob/99668b60f7ff7b6363dfc87751a18281d9a74a09/efb_telegram_master/slave_message.py#L142-L163
            #
            # Rules:
            # 1. If the picture is too large -- shorter side is greater than IMG_MIN_SIZE, send as file.
            # 2. If the picture is large and thin --
            #        longer side is greater than IMG_MAX_SIZE, and
            #        aspect ratio (longer to shorter side ratio) is greater than IMG_SIZE_RATIO,
            #    send as file.
            # 3. If the picture is too thin -- aspect ratio grater than IMG_SIZE_MAX_RATIO, send as file.

            try:
                pic_img = Image.open(msg.path)
                max_size = max(pic_img.size)
                min_size = min(pic_img.size)
                img_ratio = max_size / min_size

                if min_size > self.IMG_MIN_SIZE:
                    send_as_file = True
                elif max_size > self.IMG_MAX_SIZE and img_ratio > self.IMG_SIZE_RATIO:
                    send_as_file = True
                elif img_ratio >= self.IMG_SIZE_MAX_RATIO:
                    send_as_file = True
                else:
                    send_as_file = False
            ### patch modified 👇 ###
            # https://github.com/mpetroff/pannellum/issues/596
            # PIL.Image.DecompressionBombError: Image size (205461516 pixels) exceeds limit of 178956970 pixels, could be decompression bomb DOS attack.
            except Exception:  # Ignore when the image cannot be properly identified.
                send_as_file = False

            file_too_large = self.check_file_size(msg.file)
            edit_media = msg.edit_media
            if file_too_large:
                if old_msg_id:
                    if msg.edit_media:
                        edit_media = False
                    self.bot.send_message(chat_id=old_msg_id[0], reply_to_message_id=old_msg_id[1], text=file_too_large)
                else:
                    message = self.bot.send_message(chat_id=tg_dest, reply_to_message_id=target_msg_id, text=text,
                                                    parse_mode="HTML", reply_markup=reply_markup, disable_notification=silent,
                                                    prefix=msg_template, suffix=reactions)
                    message.reply_text(file_too_large)
                    return message

            if old_msg_id:
                try:
                    if edit_media:
                        if send_as_file:
                            media = InputMediaDocument(msg.file)
                        else:
                            media = InputMediaPhoto(msg.file)
                        self.bot.edit_message_media(chat_id=old_msg_id[0], message_id=old_msg_id[1], media=media)
                    return self.bot.edit_message_caption(chat_id=old_msg_id[0], message_id=old_msg_id[1],
                                                         reply_markup=reply_markup,
                                                         prefix=msg_template, suffix=reactions, caption=text, parse_mode="HTML")
                except telegram.error.BadRequest:
                    # Send as an reply if cannot edit previous message.
                    if old_msg_id[0] == str(target_msg_id):
                        target_msg_id = target_msg_id or old_msg_id[1]
                    msg.file.seek(0)

            if send_as_file:
                return self.bot.send_document(tg_dest, msg.file, prefix=msg_template, suffix=reactions,
                                              caption=text, parse_mode="HTML", filename=msg.filename,
                                              reply_to_message_id=target_msg_id,
                                              reply_markup=reply_markup,
                                              disable_notification=silent)
            else:
                try:
                    return self.bot.send_photo(tg_dest, msg.file, prefix=msg_template, suffix=reactions,
                                               caption=text, parse_mode="HTML",
                                               reply_to_message_id=target_msg_id,
                                               reply_markup=reply_markup,
                                               disable_notification=silent)
                except telegram.error.BadRequest as e:
                    self.logger.error('[%s] Failed to send it as image, sending as document. Reason: %s',
                                      msg.uid, e)
                    return self.bot.send_document(tg_dest, msg.file, prefix=msg_template, suffix=reactions,
                                                  caption=text, parse_mode="HTML", filename=msg.filename,
                                                  reply_to_message_id=target_msg_id,
                                                  reply_markup=reply_markup,
                                                  disable_notification=silent)
        finally:
            if msg.file:
                msg.file.close()

    # efb_telegram_master/slave_message.py
    def get_slave_msg_dest(self, msg: Message) -> Tuple[str, Optional[TelegramChatID]]:
        """Get the Telegram destination of a message with its header.

        Returns:
            msg_template (str): header of the message.
            tg_dest (Optional[str]): Telegram destination chat, None if muted.
        """
        xid = msg.uid
        msg.chat = self.chat_manager.update_chat_obj(msg.chat)
        msg.author = self.chat_manager.get_or_enrol_member(msg.chat, msg.author)

        chat_uid = utils.chat_id_to_str(chat=msg.chat)
        tg_chats = self.db.get_chat_assoc(slave_uid=chat_uid)
        tg_chat = None

        if tg_chats:
            tg_chat = tg_chats[0]
        self.logger.debug("[%s] The message should deliver to %s", xid, tg_chat)

        ### patch modified start 👇 ###
        # 如果没有绑定，判断同名的tg群组，自动尝试关联
        if not tg_chat:
            t_chat = convert_chat(self.db, msg.chat)
            tg_mp = self.channel.config.get('tg_mp')

            master_name = f"{t_chat.alias or t_chat.name}"
            tg_group = self.tgdb.get_tg_groups(master_name=master_name)

            if tg_group is not None:
                auto_detect_tg_dest = tg_group.master_id
                multi_slaves = bool(tg_group.multi_slaves)
                tg_chat = utils.chat_id_to_str(
                    self.channel.channel_id, auto_detect_tg_dest)
                t_chat.link(self.channel.channel_id,
                            auto_detect_tg_dest, multi_slaves)

            elif t_chat.vendor_specific.get('is_mp', False) and tg_mp:
                tg_chat = utils.chat_id_to_str(self.channel.channel_id, tg_mp)
                t_chat.link(self.channel.channel_id, tg_mp, True)

        else:
            # 已绑定的，判断是否有更新名称，并且在tg_groups内有映射，则更新映射新的微信名称
            if msg.author and isinstance(msg.chat, GroupChat):
                self.mod_tit_pattern = re.compile(r'修改群名为“(.*)”')
                result = self.mod_tit_pattern.findall(msg.text)
                if len(result) > 0:
                    new_tit = result[0]
                    self.tgdb.update_tg_groups(
                        int(utils.chat_id_str_to_id(tg_chat)[1]), new_tit)
        ### patch modified end 👆 ###

        singly_linked = True
        if tg_chat:
            slaves = self.db.get_chat_assoc(master_uid=tg_chat)
            if slaves and len(slaves) > 1:
                singly_linked = False
                self.logger.debug("[%s] Sender is linked with other chats in a Telegram group.", xid)
        self.logger.debug("[%s] Message is in chat %s", xid, msg.chat)

        # Generate chat text template & Decide type target
        tg_dest = TelegramChatID(self.channel.config['admins'][0])

        if tg_chat:  # if this chat is linked
            tg_dest = TelegramChatID(int(utils.chat_id_str_to_id(tg_chat)[1]))
        else:
            singly_linked = False

        msg_template = self.generate_message_template(msg, singly_linked)
        self.logger.debug("[%s] Message is sent to Telegram chat %s, with header \"%s\".",
                          xid, tg_dest, msg_template)

        if self.chat_dest_cache.get(str(tg_dest)) != chat_uid:
            self.chat_dest_cache.remove(str(tg_dest))

        return msg_template, tg_dest

    # efb_telegram_master/slave_message.py
    def send_status(self, status: Status):
        if isinstance(status, ChatUpdates):
            self.logger.debug("Received chat updates from channel %s", status.channel)
            for i in status.removed_chats:
                self.db.delete_slave_chat_info(status.channel.channel_id, i)
                self.chat_manager.delete_chat_object(status.channel.channel_id, i)
            for i in itertools.chain(status.new_chats, status.modified_chats):
                chat = status.channel.get_chat(i)
                self.chat_manager.update_chat_obj(chat, full_update=True)
        elif isinstance(status, MemberUpdates):
            self.logger.debug("Received member updates from channel %s about group %s",
                              status.channel, status.chat_id)
            for i in status.removed_members:
                self.db.delete_slave_chat_info(status.channel.channel_id, i, status.chat_id)
            self.chat_manager.delete_chat_members(status.channel.channel_id, status.chat_id, status.removed_members)
            chat = status.channel.get_chat(status.chat_id)
            self.chat_manager.update_chat_obj(chat, full_update=True)
        elif isinstance(status, MessageRemoval):
            self.logger.debug("Received message removal request from channel %s on message %s",
                              status.source_channel, status.message)
            old_msg = self.db.get_msg_log(
                slave_msg_id=status.message.uid,
                slave_origin_uid=utils.chat_id_to_str(chat=status.message.chat))
            if old_msg:
                old_msg_id: OldMsgID = utils.message_id_str_to_id(old_msg.master_msg_id)
                self.logger.debug("Found message to delete in Telegram: %s.%s",
                                  *old_msg_id)
                try:
                    if not self.channel.flag('prevent_message_removal'):
                        self.bot.delete_message(*old_msg_id)
                        return
                except telegram.TelegramError:
                    pass
                ### patch modified start 👇 ###
                if old_msg.msg_type in ('Text', 'Image', 'File'):
                    # self.logger.log(99, 'old_msg.msg_type: %s', old_msg.msg_type)
                    a_module, a_id, a_grp = utils.chat_id_str_to_id(old_msg.slave_member_uid)
                    author = self.chat_manager.get_chat_member(a_module, a_grp, a_id)
                    text = old_msg.text
                    if a_id != a_grp:
                        status.message.author = author
                        message_template = self.generate_message_template(status.message, str(self.channel.config['admins'][0]) != old_msg_id[0])
                        text = f"{message_template}\n" + text
                    elif not text:
                        text = 'deleted'
                    text = self.escape_markdown2(text)  #  + ' [❌]'
                    if old_msg.msg_type == 'Text':
                        self.bot.edit_message_text(chat_id=old_msg_id[0],
                                        text=f"~{text}~",
                                        message_id=old_msg_id[1],
                                        parse_mode="MarkdownV2")
                    else:
                        self.bot.edit_message_caption(chat_id=old_msg_id[0],
                                        caption=f"~{text}~",
                                        message_id=old_msg_id[1],
                                        parse_mode="MarkdownV2")
                else:
                ### patch modified end 👆 ###
                    self.bot.send_message(chat_id=old_msg_id[0],
                                      text=self._("Message is removed in remote chat."),
                                      reply_to_message_id=old_msg_id[1])
            else:
                self.logger.info('Was supposed to delete a message, '
                                 'but it does not exist in database: %s', status)
        elif isinstance(status, MessageReactionsUpdate):
            self.update_reactions(status)
        else:
            self.logger.error('Received an unsupported type of status: %s', status)


    # efb_telegram_master/chat_binding.py
    def update_group_info(self, update: Update, context: CallbackContext):
        """
        Update the title and profile picture of singly-linked Telegram group
        according to the linked remote chat.

        Triggered by ``/update_info`` command.
        """
        if update.effective_chat.type == telegram.Chat.PRIVATE:
            return self.bot.reply_error(update, self._('Send /update_info to a group where this bot is a group admin '
                                                       'to update group title, description and profile picture.'))
        forwarded_from_chat = update.effective_message.forward_from_chat
        if forwarded_from_chat and forwarded_from_chat.type == telegram.Chat.CHANNEL:
            tg_chat = forwarded_from_chat.id
        else:
            tg_chat = update.effective_chat.id
        chats = self.db.get_chat_assoc(master_uid=utils.chat_id_to_str(channel=self.channel,
                                                                       chat_uid=tg_chat))
        if len(chats) != 1:
            return self.bot.reply_error(update, self.ngettext('This only works in a group linked with one chat. '
                                                              'Currently {0} chat linked to this group.',
                                                              'This only works in a group linked with one chat. '
                                                              'Currently {0} chats linked to this group.',
                                                              len(chats)).format(len(chats)))
        picture: Optional[IO] = None
        pic_resized: Optional[IO] = None
        channel_id, chat_uid, _ = utils.chat_id_str_to_id(chats[0])
        if channel_id not in coordinator.slaves:
            self.logger.exception(f"Channel linked ({channel_id}) is not found.")
            return self.bot.reply_error(update, self._('Channel linked ({channel}) is not found.')
                                        .format(channel=channel_id))
        channel = coordinator.slaves[channel_id]
        try:
            chat = self.chat_manager.update_chat_obj(channel.get_chat(chat_uid), full_update=True)
            ### patch modified start 👇 ###
            chat_title = f"{chat.alias or chat.name}"
            self.tgdb.add_tg_groups(master_id=tg_chat, master_name=chat_title)
            self.bot.set_chat_title(tg_chat, self.truncate_ellipsis(chat_title if self.REMOVE_EMOJI_IN_TITLE else chat.chat_title, self.MAX_LEN_CHAT_TITLE))
            ### patch modified end 👆 ###
            # Update remote group members list to Telegram group description if available
            desc = chat.description
            if isinstance(chat, ETMGroupChat):
                names = [i.long_name for i in chat.members if not isinstance(i, SystemChatMember)]
                # TRANSLATORS: Separator between group members in a Telegram group description generated by /update_info
                members = self._(", ").join(names)
                if desc:
                    desc += "\n"
                desc += self.ngettext("{count} group member: {list}", "{count} group members: {list}",
                                      len(names)).format(count=len(names), list=members)
            if desc:
                try:
                    self.bot.set_chat_description(
                        tg_chat, self.truncate_ellipsis(desc, self.MAX_LEN_CHAT_DESC))
                except BadRequest as e:
                    if "Chat description is not modified" in e.message:
                        pass
                    else:
                        self.logger.exception("Exception occurred while trying to update chat description: %s", e)
                except TelegramError as e:  # description is not updated
                    self.logger.exception("Exception occurred while trying to update chat description: %s", e)

            picture = channel.get_chat_picture(chat)
            if not picture:
                raise EFBOperationNotSupported()
            pic_img = Image.open(picture)

            if pic_img.size[0] < self.TELEGRAM_MIN_PROFILE_PICTURE_SIZE or \
                    pic_img.size[1] < self.TELEGRAM_MIN_PROFILE_PICTURE_SIZE:
                # resize
                scale = self.TELEGRAM_MIN_PROFILE_PICTURE_SIZE / min(pic_img.size)
                pic_resized = io.BytesIO()
                pic_img.resize(tuple(map(lambda a: int(scale * a), pic_img.size)), Image.BICUBIC) \
                    .save(pic_resized, 'PNG')
                pic_resized.seek(0)

            picture.seek(0)

            self.bot.set_chat_photo(tg_chat, pic_resized or picture)
            ### patch modified 👇 ###
            # update.message.reply_text(self._('Chat details updated.'))
        except EFBChatNotFound:
            self.logger.exception("Chat linked (%s) is not found in the slave channel "
                                  "(%s).", channel_id, chat_uid)
            return self.bot.reply_error(update, self._("Chat linked ({chat_uid}) is not found in the slave channel "
                                                       "({channel_name}, {channel_id}).")
                                        .format(channel_name=channel.channel_name, channel_id=channel_id,
                                                chat_uid=chat_uid))
        except telegram.TelegramError as e:
            self.logger.exception("Error occurred while update chat details.")
            return self.bot.reply_error(update, self._('Error occurred while update chat details.\n'
                                                       '{0}'.format(e.message)))
        except EFBOperationNotSupported:
            return self.bot.reply_error(update, self._('No profile picture provided from this chat.'))
        except Exception as e:
            self.logger.exception("Unknown error caught when querying chat.")
            return self.bot.reply_error(update, self._('Error occurred while update chat details. \n'
                                                       '{0}'.format(e)))
        finally:
            if picture and getattr(picture, 'close', None):
                picture.close()
            if pic_resized and getattr(pic_resized, 'close', None):
                pic_resized.close()

    def relate_group(self, update: Update, context: CallbackContext):

        if update.effective_chat.id == self.bot.get_me().id:
            return self.bot.reply_error(update, self._('Send /relate_group in a group.'))
        if not getattr(update.message, "reply_to_message", None):
            return self.bot.reply_error(update, self._('Reply to a msg with this command to relate it with this telegram group.'))

        msg_log = self.db.get_msg_log(master_msg_id=utils.message_id_to_str(
            update.message.reply_to_message.chat.id,
            update.message.reply_to_message.message_id))
        if not msg_log:
            return update.message.reply_text(self._("The message you replied to is not recorded in ETM database."))

        if update.effective_message.forward_from_chat and \
                update.effective_message.forward_from_chat.type == telegram.Chat.CHANNEL:
            tg_chat = update.effective_message.forward_from_chat.id
        else:
            tg_chat = update.effective_chat.id

        channel_id, chat_uid, _ = utils.chat_id_str_to_id(msg_log.slave_origin_uid)
        try:
            channel = coordinator.slaves[channel_id]
            chat = channel.get_chat(chat_uid)
            if chat is None:
                raise EFBChatNotFound()
            chat = convert_chat(self.db, chat)

            chat_title=f"{chat.alias or chat.name}"
            self.tgdb.add_tg_groups(master_id=tg_chat, master_name=chat_title, multi_slaves=True)
            update.message.reply_text(self._('Chat related.'))

        except KeyError:
            self.logger.exception(f"Channel linked ({channel_id}) is not found.")
            return self.bot.reply_error(update, self._('Channel linked ({channel}) is not found.')
                                        .format(channel=channel_id))
        except EFBChatNotFound:
            self.logger.exception("Chat linked is not found in channel.")
            return self.bot.reply_error(update, self._('Chat linked is not found in channel.'))
        except Exception as e:
            self.logger.exception("Unknown error caught when querying chat.")
            return self.bot.reply_error(update, self._('Error occurred while update chat details. \n'
                                                       '{0}'.format(e)))

    def release_group(self, update: Update, context: CallbackContext):
        '''
            删除微信会话绑定关系
        '''

        if update.effective_chat.id == self.bot.get_me().id:
            return self.bot.reply_error(update, self._('Send /relate_group in a group.'))
        if not getattr(update.message, "reply_to_message", None):
            chat_id = update.effective_chat.id
            self.tgdb.remove_tg_groups(master_id=chat_id)
            return update.message.reply_text(self._('All slave chats released.'))

        msg_log = self.db.get_msg_log(master_msg_id=utils.message_id_to_str(
            update.message.reply_to_message.chat.id,
            update.message.reply_to_message.message_id))
        if not msg_log:
            return update.message.reply_text(self._("The message you replied to is not recorded in ETM database."))

        if update.effective_message.forward_from_chat and \
                update.effective_message.forward_from_chat.type == telegram.Chat.CHANNEL:
            tg_chat = update.effective_message.forward_from_chat.id
        else:
            tg_chat = update.effective_chat.id

        channel_id, chat_uid, _ = utils.chat_id_str_to_id(msg_log.slave_origin_uid)
        try:
            channel = coordinator.slaves[channel_id]
            chat = channel.get_chat(chat_uid)
            if chat is None:
                raise EFBChatNotFound()
            chat = convert_chat(self.db, chat)

            chat_title=f"{chat.alias or chat.name}"
            self.tgdb.remove_tg_groups(master_name=chat_title)
            update.message.reply_text(self._('Chat released.'))

        except KeyError:
            self.logger.exception(f"Channel linked ({channel_id}) is not found.")
            return self.bot.reply_error(update, self._('Channel linked ({channel}) is not found.')
                                        .format(channel=channel_id))
        except EFBChatNotFound:
            self.logger.exception("Chat linked is not found in channel.")
            return self.bot.reply_error(update, self._('Chat linked is not found in channel.'))

        except Exception as e:
            self.logger.exception("Unknown error caught when release chat.")
            return self.bot.reply_error(update, self._('Error occurred while release chat. \n'
                                                       '{0}'.format(e)))

    # efb_telegram_master/master_message.py
    def msg(self, update: Update, context: CallbackContext):
        """
        Process, wrap and dispatch messages from user.
        """
        assert isinstance(update, Update)
        assert update.effective_message
        assert update.effective_chat

        message: Message = update.effective_message
        mid = utils.message_id_to_str(update=update)

        self.logger.debug("[%s] Received message from Telegram: %s", mid, message.to_dict())

        destination = None
        edited = None
        quote = False

        if update.edited_message or update.edited_channel_post:
            self.logger.debug('[%s] Message is edited: %s', mid, message.edit_date)
            msg_log = self.db.get_msg_log(master_msg_id=utils.message_id_to_str(update=update))
            if not msg_log or msg_log.slave_message_id == self.db.FAIL_FLAG:
                message.reply_text(self._("Error: This message cannot be edited, and thus is not sent. (ME01)"), quote=True)
                return
            destination = msg_log.slave_origin_uid
            edited = msg_log
            quote = msg_log.build_etm_msg(self.chat_manager).target is not None

        if destination is None:
            destination = self.get_singly_linked_chat_id_str(update.effective_chat)
            if destination:
                # if the chat is singly-linked
                quote = message.reply_to_message is not None
                self.logger.debug("[%s] Chat %s is singly-linked to %s", mid, message.chat, destination)

        if destination is None:  # not singly linked
            quote = False
            self.logger.debug("[%s] Chat %s is not singly-linked", mid, update.effective_chat)
            reply_to = message.reply_to_message
            cached_dest = self.chat_dest_cache.get(str(message.chat.id))
            if reply_to:
                self.logger.debug("[%s] Message is quote-replying to %s", mid, reply_to)
                dest_msg = self.db.get_msg_log(
                    master_msg_id=utils.message_id_to_str(
                        TelegramChatID(reply_to.chat.id),
                        TelegramMessageID(reply_to.message_id)
                )
                )
                if dest_msg:
                    destination = dest_msg.slave_origin_uid
                    self.chat_dest_cache.set(str(message.chat.id), destination)
                    self.logger.debug("[%s] Quoted message is found in database with destination: %s", mid, destination)
            elif cached_dest:
                self.logger.debug("[%s] Cached destination found: %s", mid, cached_dest)
                destination = cached_dest
                self._send_cached_chat_warning(update, TelegramChatID(message.chat.id), cached_dest)

        self.logger.debug("[%s] Destination chat = %s", mid, destination)

        if destination is None:
            self.logger.debug("[%s] Destination is not found for this message", mid)
            candidates = (
                 self.db.get_recent_slave_chats(TelegramChatID(message.chat.id), limit=5) or
                 self.db.get_chat_assoc(master_uid=utils.chat_id_to_str(self.channel_id, ChatID(str(message.chat.id))))[:5]
            )
            if candidates:
                self.logger.debug("[%s] Candidate suggestions are found for this message: %s", mid, candidates)
                tg_err_msg = message.reply_text(self._("Error: No recipient specified.\n"
                                                       "Please reply to a previous message. (MS01)"), quote=True)
                self.channel.chat_binding.register_suggestions(update, candidates,
                                                               TelegramChatID(update.effective_chat.id),
                                                               TelegramMessageID(tg_err_msg.message_id))
            else:
                ### patch modified start 👇 ###
                chat_relation = self.tgdb.get_wx_groups(master_id=message.chat.id)
                if chat_relation is not None:
                    try:
                        relate_chat = wxpy.utils.ensure_one(self.channel_ews.bot.chats().search(chat_relation.master_name))
                        # self.logger.log(99, "relate_chat: [%s] [%s]", relate_chat.puid, relate_chat.__dict__)
                        destination = f"blueset.wechat {relate_chat.puid}"
                        return self.process_telegram_message(update, context, destination, quote=quote)
                    except ValueError:
                        self.logger.log(99, "guess destination chat failed.")
                    except Exception:
                        self.logger.exception('guess destination chat error.')
                ### patch modified end 👆 ###
                self.logger.debug("[%s] Candidate suggestions not found, give up.", mid)
                message.reply_text(self._("Error: No recipient specified.\n"
                                          "Please reply to a previous message. (MS02)"), quote=True)
        else:
            return self.process_telegram_message(update, context, destination, quote=quote, edited=edited)

    # efb_telegram_master/master_message.py
    def process_telegram_message(self, update: Update, context: CallbackContext,
                                 destination: EFBChannelChatIDStr, quote: bool = False,
                                 edited: Optional["MsgLog"] = None):
        """
        Process messages came from Telegram.

        Args:
            update: Telegram message update
            context: PTB update context
            destination: Destination of the message specified.
            quote: If the message shall quote another one
            edited: old message log entry if the message can be edited.
        """
        assert isinstance(update, Update)
        assert update.effective_message

        # Message ID for logging
        message_id = utils.message_id_to_str(update=update)

        ### patch modified 👇 ###
        message: telegram.Message = update.effective_message

        channel, uid, gid = utils.chat_id_str_to_id(destination)
        if channel not in coordinator.slaves:
            return self.bot.reply_error(update,
                                        self._("Internal error: Slave channel “{0}” not found.").format(channel))

        m = ETMMsg()
        log_message = True
        try:
            m.uid = MessageID(message_id)
            # Store Telegram message type
            m.type_telegram = mtype = get_msg_type(message)

            if self.TYPE_DICT.get(mtype, None):
                m.type = self.TYPE_DICT[mtype]
                self.logger.debug("[%s] EFB message type: %s", message_id, mtype)
            else:
                self.logger.info("[%s] Message type %s is not supported by ETM", message_id, mtype)
                raise EFBMessageTypeNotSupported(
                    self._("{type_name} messages are not supported by EFB Telegram Master channel.")
                        .format(type_name=mtype.name))

            m.put_telegram_file(message)
            # Chat and author related stuff
            m.chat = self.chat_manager.get_chat(channel, uid, build_dummy=True)
            m.author = m.chat.self or m.chat.add_self()

            m.deliver_to = coordinator.slaves[channel]
            ### patch modified 👇 ###
            m.is_forward = bool(getattr(message, "forward_from", None))

            if quote:
                self.attach_target_message(message, m, channel)
            # Type specific stuff
            self.logger.debug("[%s] Message type from Telegram: %s", message_id, mtype)

            if m.type not in coordinator.slaves[channel].supported_message_types:
                self.logger.info("[%s] Message type %s is not supported by channel %s",
                                 message_id, m.type.name, channel)
                raise EFBMessageTypeNotSupported(
                    self._("{type_name} messages are not supported by slave channel {channel_name}.")
                        .format(type_name=m.type.name,
                                channel_name=coordinator.slaves[channel].channel_name))

            # Convert message text and caption to markdown
            # Keep original text if what *_markdown_2 did is just escaping the text.
            msg_md_text = message.text and message.text_markdown_v2 or ""
            if message.text and msg_md_text == escape_markdown(message.text, version=2):
                msg_md_text = message.text
            msg_md_text = msg_md_text or ""

            msg_md_caption = message.caption and message.caption_markdown_v2 or ""
            if message.caption and msg_md_caption == escape_markdown(message.caption, version=2):
                msg_md_caption = message.caption
            msg_md_caption = msg_md_caption or ""

            # Flag for edited message
            if edited:
                m.edit = True
                text = msg_md_text or msg_md_caption

                m.uid = edited.slave_message_id
                if text.startswith(self.DELETE_FLAG):
                    coordinator.send_status(MessageRemoval(
                        source_channel=self.channel,
                        destination_channel=coordinator.slaves[channel],
                        message=m
                    ))
                    if not self.channel.flag('prevent_message_removal'):
                        try:
                            message.delete()
                        except TelegramError:
                            message.reply_text(self._("Message is removed in remote chat."))
                    else:
                        message.reply_text(self._("Message is removed in remote chat."))
                    log_message = False
                    return
                self.logger.debug('[%s] Message is edited (%s)', m.uid, m.edit)
                if m.file_unique_id and m.file_unique_id != edited.file_unique_id:
                    self.logger.debug("[%s] Message media is edited (%s -> %s)", m.uid, edited.file_unique_id, m.file_unique_id)
                    m.edit_media = True

            ### patch modified start 👇 ###
            # 以rm开头回复来撤回自己发送的消息
            if message.reply_to_message and message.reply_to_message.from_user and message.reply_to_message.from_user.id == message.from_user.id and msg_md_text.startswith(self.DELETE_FLAG):
                m.edit = True
                m.edit_media = True
                msg_log = self.db.get_msg_log(master_msg_id=utils.message_id_to_str(
                            message.reply_to_message.chat.id,
                            message.reply_to_message.message_id))
                if not msg_log or msg_log.slave_message_id == self.db.FAIL_FLAG:
                    raise EFBMessageNotFound()
                m.uid = msg_log.slave_message_id
                coordinator.send_status(MessageRemoval(
                    source_channel=self.channel,
                    destination_channel=coordinator.slaves[channel],
                    message=m
                ))
                if not self.channel.flag('prevent_message_removal'):
                    try:
                        message.delete()
                    except telegram.TelegramError:
                        message.reply_text(self._("Message is removed in remote chat."), disable_notification=True)
                else:
                    message.reply_text(self._("Message is removed in remote chat."), disable_notification=True)
                # self.db.delete_msg_log(master_msg_id=utils.message_id_to_str(
                #         message.reply_to_message.chat.id,
                #         message.reply_to_message.message_id))
                log_message = False
                return
            ### patch modified end 👆 ###

            # Enclose message as an Message object by message type.
            if mtype is TGMsgType.Text:
                m.text = msg_md_text
            elif mtype is TGMsgType.Photo:
                assert message.photo
                m.text = msg_md_caption
                m.mime = "image/jpeg"
                self._check_file_download(message.photo[-1])
            elif mtype in (TGMsgType.Sticker, TGMsgType.AnimatedSticker):
                assert message.sticker
                # Convert WebP to the more common PNG
                m.text = ""
                self._check_file_download(message.sticker)
            elif mtype is TGMsgType.Animation:
                assert message.animation
                m.text = msg_md_caption
                self.logger.debug("[%s] Telegram message is a \"Telegram GIF\".", message_id)
                m.filename = getattr(message.animation, "file_name", None) or None
                if m.filename and not m.filename.lower().endswith(".gif"):
                    m.filename += ".gif"
                m.mime = message.animation.mime_type or m.mime
            elif mtype is TGMsgType.Document:
                assert message.document
                m.text = msg_md_caption
                self.logger.debug("[%s] Telegram message type is document.", message_id)
                m.filename = getattr(message.document, "file_name", None) or None
                m.mime = message.document.mime_type
                self._check_file_download(message.document)
            elif mtype is TGMsgType.Video:
                assert message.video
                m.text = msg_md_caption
                m.mime = message.video.mime_type
                self._check_file_download(message.video)
            elif mtype is TGMsgType.VideoNote:
                assert message.video_note
                m.text = msg_md_caption
                self._check_file_download(message.video_note)
            elif mtype is TGMsgType.Audio:
                assert message.audio
                m.text = "%s - %s\n%s" % (
                    message.audio.title, message.audio.performer, msg_md_caption)
                m.mime = message.audio.mime_type
                self._check_file_download(message.audio)
            elif mtype is TGMsgType.Voice:
                assert message.voice
                m.text = msg_md_caption
                m.mime = message.voice.mime_type
                self._check_file_download(message.voice)
            elif mtype is TGMsgType.Location:
                # TRANSLATORS: Message body text for location messages.
                assert message.location
                m.text = self._("Location")
                m.attributes = LocationAttribute(
                    message.location.latitude,
                    message.location.longitude
                )
            elif mtype is TGMsgType.Venue:
                assert message.venue
                m.text = f"📍 {message.venue.title}\n{message.venue.address}"
                m.attributes = LocationAttribute(
                    message.venue.location.latitude,
                    message.venue.location.longitude
                )
            elif mtype is TGMsgType.Contact:
                assert message.contact
                contact: Contact = message.contact
                m.text = self._("Shared a contact: {first_name} {last_name}\n{phone_number}").format(
                    first_name=contact.first_name, last_name=contact.last_name, phone_number=contact.phone_number
                )
            elif mtype is TGMsgType.Dice:
                assert message.dice
                m.text = f"{message.dice.emoji} = {message.dice.value}"
            else:
                raise EFBMessageTypeNotSupported(self._("Message type {0} is not supported.").format(mtype.name))

            slave_msg = coordinator.send_message(m)
            if slave_msg and slave_msg.uid:
                m.uid = slave_msg.uid
            else:
                m.uid = None
        except EFBChatNotFound as e:
            self.bot.reply_error(update, e.args[0] or self._("Chat is not found."))
        except EFBMessageTypeNotSupported as e:
            self.bot.reply_error(update, e.args[0] or self._("Message type is not supported."))
        except EFBOperationNotSupported as e:
            self.bot.reply_error(update,
                                 self._("Message editing is not supported.\n\n{exception!s}".format(exception=e)))
        except EFBException as e:
            self.bot.reply_error(update, self._("Message is not sent.\n\n{exception!s}".format(exception=e)))
            self.logger.exception("Message is not sent. (update: %s, exception: %s)", update, e)
        except Exception as e:
            self.bot.reply_error(update, self._("Message is not sent.\n\n{exception!r}".format(exception=e)))
            self.logger.exception("Message is not sent. (update: %s, exception: %s)", update, e)
        finally:
            if log_message:
                self.db.add_or_update_message_log(m, update.effective_message)
                if m.file:
                    m.file.close()


    # efb_wechat_slave/slave_message.py
    def wechat_sharing_msg(self, msg: wxpy.Message):
        # This method is not wrapped by wechat_msg_meta decorator, thus no need to return Message object.
        self.logger.debug("[%s] Raw message: %s", msg.id, msg.raw)
        links = msg.articles
        if links is None:
            # If unsupported
            if msg.raw.get('Content', '') in self.UNSUPPORTED_MSG_PROMPT:
                return self.wechat_unsupported_msg(msg)
            else:
                try:
                    xml = ETree.fromstring(msg.raw.get('Content'))
                    appmsg_type = self.get_node_text(xml, './appmsg/type', "")
                    source = self.get_node_text(xml, './appinfo/appname', "")
                    if appmsg_type == '2':  # Image
                        return self.wechat_shared_image_msg(msg, source)
                    elif appmsg_type in ('3', '5'):
                        title = self.get_node_text(xml, './appmsg/title', "")
                        des = self.get_node_text(xml, './appmsg/des', "")
                        url = self.get_node_text(xml, './appmsg/url', "")
                        return self.wechat_shared_link_msg(msg, source, title, des, url)
                    elif appmsg_type in ('33', '36'):  # Mini programs (wxapp)
                        title = self.get_node_text(xml, './appmsg/sourcedisplayname', "") or \
                                self.get_node_text(xml, './appmsg/appinfo/appname', "") or \
                                self.get_node_text(xml, './appmsg/title', "")
                        ### patch modified 👇 ###
                        title = '小程序：' + title
                        des = self.get_node_text(xml, './appmsg/title', "")
                        url = self.get_node_text(xml, './appmsg/url', "")
                        return self.wechat_shared_link_msg(msg, source, title, des, url)
                    elif appmsg_type == '1':  # Strange “app message” that looks like a text link
                        msg.raw['text'] = self.get_node_text(xml, './appmsg/title', "")
                        return self.wechat_text_msg(msg)
                    ### patch modified 👇 ###
                    elif appmsg_type == '51':  # 视频号
                        title = self.get_node_text(xml, './appmsg/finderFeed/nickname', "") or \
                                self.get_node_text(xml, './appmsg/finderFeed/desc', "") or \
                                self.get_node_text(xml, './appmsg/title', "")

                        title = '视频号：' + title
                        des = self.get_node_text(xml, './appmsg/finderFeed/desc', "")
                        thumb_url = self.get_node_text(xml, './appmsg/finderFeed/mediaList/media/thumbUrl', "")  # 视频预览
                        url = self.get_node_text(xml, './appmsg/finderFeed/mediaList/media/url', "")  # 视频链接
                        return self.wechat_raw_link_msg(msg, title, des, thumb_url, url)
                        # return self.wechat_shared_link_msg(msg, source, title, des, url)
                    elif appmsg_type == '4':  # 应用分享（小红书）
                        title = ": ".join((self.get_node_text(xml, './appinfo/appname', ""),
                            self.get_node_text(xml, './appmsg/title', "") or self.get_node_text(xml, './appmsg/des', "")))

                        des = self.get_node_text(xml, './appmsg/des', "")
                        thumb_url = self.get_node_text(xml, './appmsg/lowurl', "")  # 视频预览
                        url = self.get_node_text(xml, './appmsg/url', "")  # 视频链接
                        return self.wechat_raw_link_msg(msg, title, des, thumb_url, url)
                    elif appmsg_type == '50':  # 视频号名片
                        title = self.get_node_text(xml, './appmsg/findernamecard/nickname', "") or \
                                self.get_node_text(xml, './appmsg/title', "")

                        title = '视频号名片：' + title
                        des = self.get_node_text(xml, './appmsg/findernamecard/auth_job', "")
                        url = self.get_node_text(xml, './appmsg/findernamecard/avatar', "")
                        return self.wechat_shared_link_msg(msg, source, title, des, url)
                    else:
                        # Unidentified message type
                        self.logger.error("[%s] Identified unsupported sharing message type. Raw message: %s",
                                          msg.id, msg.raw)
                        raise KeyError()
                except (TypeError, KeyError, ValueError, ETree.ParseError) as e:
                    self.logger.log(99, "Raw e: %s", e)
                    return self.wechat_unsupported_msg(msg)
        ### patch modified 👇 ###
        if self.channel_ews.flag("first_link_only"):
            links = links[:1]

        for i in links:
            self.wechat_raw_link_msg(msg, i.title, i.summary, i.cover, i.url)

    # efb_wechat_slave/__init__.py
    def send_message(self, msg: Message) -> Message:
        """Send a message to WeChat.
        Supports text, image, sticker, and file.

        Args:
            msg (channel.Message): Message Object to be sent.

        Returns:
            This method returns nothing.

        Raises:
            EFBChatNotFound:
                Raised when a chat required is not found.

            EFBMessageTypeNotSupported:
                Raised when the message type sent is not supported by the
                channel.

            EFBOperationNotSupported:
                Raised when an message edit request is sent, but not
                supported by the channel.

            EFBMessageNotFound:
                Raised when an existing message indicated is not found.
                E.g.: The message to be edited, the message referred
                in the :attr:`msg.target <.Message.target>`
                attribute.

            EFBMessageError:
                Raised when other error occurred while sending or editing the
                message.
        """
        if msg.chat == self.user_auth_chat:
            raise EFBChatNotFound

        chat: wxpy.Chat = self.chats.get_wxpy_chat_by_uid(msg.chat.uid)

        # List of "SentMessage" response for all messages sent
        r: List[wxpy.SentMessage] = []
        self.logger.info("[%s] Sending message to WeChat:\n"
                         "uid: %s\n"
                         "UserName: %s\n"
                         "NickName: %s\n"
                         "Type: %s\n"
                         "Text: %s",
                         msg.uid,
                         msg.chat.uid, chat.user_name, chat.name, msg.type, msg.text)

        try:
            chat.mark_as_read()
        except Exception as e:
            self.logger.exception(
                "[%s] Error occurred while marking chat as read. (%s)", msg.uid, e)

        send_text_only = False
        self.logger.debug('[%s] Is edited: %s', msg.uid, msg.edit)
        if msg.edit and msg.uid:
            if self.flag('delete_on_edit'):
                msg_ids = json.loads(msg.uid)
                if msg.type in self.MEDIA_MSG_TYPES and not msg.edit_media:
                    # Treat message as text message to prevent resend of media
                    msg_ids = msg_ids[1:]
                    send_text_only = True
                failed = 0
                for i in msg_ids:
                    try:
                        ews_utils.message_id_to_dummy_message(i, self).recall()
                    except wxpy.ResponseError as e:
                        self.logger.error(
                            "[%s] Trying to recall message but failed: %s", msg.uid, e)
                        failed += 1
                if failed:
                    raise EFBMessageError(
                        self.ngettext('Failed to recall {failed} out of {total} message, edited message was not sent.',
                                      'Failed to recall {failed} out of {total} messages, edited message was not sent.',
                                      len(msg_ids)).format(
                            failed=failed,
                            total=len(msg_ids)
                        ))
                # Not caching message ID as message recall feedback is not needed in edit mode
            else:
                raise EFBOperationNotSupported()
        if send_text_only or msg.type in [MsgType.Text, MsgType.Link]:
            if isinstance(msg.target, Message):
                max_length = self.flag("max_quote_length")
                qt_txt = msg.target.text or msg.target.type.name
                if max_length > 0:
                    if len(qt_txt) >= max_length:
                        tgt_text = qt_txt[:max_length]
                        tgt_text += "…"
                    else:
                        tgt_text = qt_txt
                elif max_length < 0:
                    tgt_text = qt_txt
                else:
                    tgt_text = ""
                if isinstance(chat, wxpy.Group) and not isinstance(msg.target.author, SelfChatMember):
                    tgt_alias = "@%s\u2005：" % msg.target.author.display_name
                else:
                    tgt_alias = ""
                msg.text = f"「{tgt_alias}{tgt_text}」\n- - - - - - - - - - - - - - -\n{msg.text}"
            r.append(self._bot_send_msg(chat, msg.text))
            self.logger.debug(
                '[%s] Sent as a text message. %s', msg.uid, msg.text)
        elif msg.type in (MsgType.Image, MsgType.Sticker, MsgType.Animation):
            self.logger.info("[%s] Image/GIF/Sticker %s", msg.uid, msg.type)

            convert_to = None
            file = msg.file
            assert file is not None

            if self.flag('send_stickers_and_gif_as_jpeg'):
                if msg.type == MsgType.Sticker or msg.mime == "image/gif":
                    convert_to = "image/jpeg"
            else:
                if msg.type == MsgType.Sticker:
                    convert_to = "image/gif"

            if convert_to == "image/gif":
                with NamedTemporaryFile(suffix=".gif") as f:
                    try:
                        img = Image.open(file)
                        try:
                            alpha = img.split()[3]
                            mask = Image.eval(
                                alpha, lambda a: 255 if a <= 128 else 0)
                        except IndexError:
                            mask = Image.eval(img.split()[0], lambda a: 0)
                        img = img.convert('RGB').convert(
                            'P', palette=Image.ADAPTIVE, colors=255)
                        img.paste(255, mask)
                        img.save(f, transparency=255)
                        msg.path = Path(f.name)
                        self.logger.debug(
                            '[%s] Image converted from %s to GIF', msg.uid, msg.mime)
                        file.close()
                        if f.seek(0, 2) > self.MAX_FILE_SIZE:
                            raise EFBMessageError(
                                self._("Image size is too large. (IS02)"))
                        f.seek(0)
                        r.append(self._bot_send_image(chat, f.name, f))
                    finally:
                        if not file.closed:
                            file.close()
            elif convert_to == "image/jpeg":
                with NamedTemporaryFile(suffix=".jpg") as f:
                    try:
                        img = Image.open(file).convert('RGBA')
                        out = Image.new("RGBA", img.size, (255, 255, 255, 255))
                        out.paste(img, img)
                        out.convert('RGB').save(f)
                        msg.path = Path(f.name)
                        self.logger.debug(
                            '[%s] Image converted from %s to JPEG', msg.uid, msg.mime)
                        file.close()
                        if f.seek(0, 2) > self.MAX_FILE_SIZE:
                            raise EFBMessageError(
                                self._("Image size is too large. (IS02)"))
                        f.seek(0)
                        r.append(self._bot_send_image(chat, f.name, f))
                    finally:
                        if not file.closed:
                            file.close()
            else:
                try:
                    if file.seek(0, 2) > self.MAX_FILE_SIZE:
                        raise EFBMessageError(
                            self._("Image size is too large. (IS01)"))
                    file.seek(0)
                    ### patch modified start 👇 ###
                    if msg.type == MsgType.Animation:
                        try:
                            metadata = ffmpeg.probe(file.name)
                            # self.logger.log(99, "file info: %s", metadata)
                            if int(metadata['format']['bit_rate']) > 500000:
                                gif_file = NamedTemporaryFile(suffix='.gif')
                                stream = ffmpeg.input(file.name)
                                stream = stream.filter("scale", 320, -2).filter("fps", 8)
                                stream.output(gif_file.name).overwrite_output().run()
                                # self.logger.log(99, "new file info %s", ffmpeg.probe(gif_file.name))
                                file = gif_file
                                file.seek(0)
                        except Exception as e:
                            self.logger.exception("Exception occurred while trying to compress img: %s", e)
                    ### patch modified end 👆 ###
                    self.logger.debug(
                        "[%s] Sending %s (image) to WeChat.", msg.uid, msg.path)
                    filename = msg.filename or (msg.path and msg.path.name)
                    assert filename
                    r.append(self._bot_send_image(chat, filename, file))
                finally:
                    if not file.closed:
                        file.close()
            ### patch modified 👇 ###
            if msg.text and not msg.is_forward:
                r.append(self._bot_send_msg(chat, msg.text))
        elif msg.type in (MsgType.File, MsgType.Audio):
            self.logger.info("[%s] Sending %s to WeChat\nFileName: %s\nPath: %s\nFilename: %s",
                             msg.uid, msg.type, msg.text, msg.path, msg.filename)
            filename = msg.filename or (msg.path and msg.path.name)
            assert filename and msg.file
            r.append(self._bot_send_file(chat, filename, file=msg.file))
            ### patch modified 👇 ###
            if msg.text and not msg.is_forward:
                self._bot_send_msg(chat, msg.text)
            if not msg.file.closed:
                msg.file.close()
        elif msg.type == MsgType.Video:
            self.logger.info(
                "[%s] Sending video to WeChat\nFileName: %s\nPath: %s", msg.uid, msg.text, msg.path)
            filename = msg.filename or (msg.path and msg.path.name)
            assert filename and msg.file
            r.append(self._bot_send_video(chat, filename, file=msg.file))
            ### patch modified 👇 ###
            if msg.text and not msg.is_forward:
                r.append(self._bot_send_msg(chat, msg.text))
            if not msg.file.closed:
                msg.file.close()
        else:
            raise EFBMessageTypeNotSupported()

        msg.uid = ews_utils.generate_message_uid(r)
        self.logger.debug(
            'WeChat message is assigned with unique ID: %s', msg.uid)
        return msg

    # efb_wechat_slave/vendor/wxpy/api/bot.py
    def _process_message(self, msg):
        """
        处理接收到的消息
        """
        if not self.alive:
            return

        config = self.registered.get_config(msg)

        self.logger.debug('{}: new message (func: {}):\n{}'.format(
            ### patch modified 👇 ###
            self.channel_ews.bot, config.func.__name__ if config else None, msg))

        if config:

            def process():
                # noinspection PyBroadException
                try:
                    ret = config.func(msg)
                    if ret is not None:
                        msg.reply(ret)
                except:
                    self.logger.exception('an error occurred in {}.'.format(config.func))
                ### patch modified 👇 ###
                if self.auto_mark_as_read and not msg.type == SYSTEM and msg.sender != self.channel_ews.bot.self:
                    try:
                        ### patch modified start 👇 ###
                        # msg.chat.mark_as_read()
                        if not self.mark_as_read_cache.get(msg.chat.puid):
                            self.mark_as_read_cache.set(msg.chat.puid, True, DALAY_MARK_AS_READ)
                            schedule.enter(DALAY_MARK_AS_READ, 0, msg.chat.mark_as_read, ())
                            schedule.run()
                        ### patch modified end 👆 ###
                    except ResponseError as e:
                        self.logger.warning('failed to mark as read: {}'.format(e))

            if config.run_async:
                start_new_thread(process, use_caller_name=True)
            else:
                process()


    def get_slave_chat_contact_alias(self, slave_chat_uid: Optional[ChatID] = None) -> Optional[SlaveChatInfo]:
        """
        Get cached slave chat info from database.

        Returns:
            SlaveChatInfo|None: The matching slave chat info, None if not exist.
        """
        if slave_chat_uid is None:
            raise None
        if slave_chat_uid == '__self__':
            return 'You'
        try:
            contact = SlaveChatInfo.select() \
                .where((SlaveChatInfo.slave_chat_uid == slave_chat_uid) &
                       (SlaveChatInfo.slave_chat_group_id.is_null(True))).first()
            if not contact or not contact.slave_chat_alias:
                contact = SlaveChatInfo.select() \
                    .where((SlaveChatInfo.slave_chat_uid == slave_chat_uid) &
                           (SlaveChatInfo.slave_chat_alias.is_null(False))).first()
                if not contact or not contact.slave_chat_alias:
                    return None
            # TODO cache
            return contact.slave_chat_alias
        except DoesNotExist:
            return None

    @staticmethod
    def escape_markdown2(text):
        """Helper function to escape telegram markup symbols."""
        escape_chars = '_\*\[\]\(\)~`>#\+\-=\|\{\}\.\!'
        return re.sub(r'([%s])' % escape_chars, r'\\\1', text)
