# coding: utf-8
import io
import os
import re
import json
import time
import sched
import logging
import telegram

from PIL import Image
from tempfile import NamedTemporaryFile
from xml.etree import ElementTree as ETree
from xml.etree.ElementTree import Element

from typing import Tuple, Optional, List, overload, Callable, Sequence, Any, Dict
from telegram import Update, Message, Chat, TelegramError
from telegram.ext import CallbackContext, Filters, MessageHandler, CommandHandler
from telegram.utils.helpers import escape_markdown

from ehforwarderbot import EFBMiddleware, EFBMsg, EFBStatus, \
    EFBChat, coordinator, EFBChannel, utils as efb_utils
from ehforwarderbot.constants import MsgType, ChatType
from ehforwarderbot.exceptions import EFBChatNotFound, EFBOperationNotSupported, EFBMessageTypeNotSupported, \
    EFBMessageNotFound, EFBMessageError, EFBException
from ehforwarderbot.types import ModuleID, ChatID, MessageID
from ehforwarderbot.message import EFBMsgLocationAttribute
from ehforwarderbot.status import EFBMessageRemoval

from efb_telegram_master import ETMChat, utils
from efb_telegram_master.utils import TelegramMessageID, TelegramChatID, EFBChannelChatIDStr, TgChatMsgIDStr
from efb_telegram_master.constants import Emoji
from efb_telegram_master.message import ETMMsg
from efb_telegram_master.msg_type import TGMsgType
from efb_telegram_master.chat_destination_cache import ChatDestinationCache


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
            master_id (str): telegram group id
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
class PatchMiddleware(EFBMiddleware):
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

        if hasattr(coordinator, "master") and isinstance(coordinator.master, EFBChannel):
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

            self._send_cached_chat_warning = self.master_messages._send_cached_chat_warning
            self._check_file_download = self.master_messages._check_file_download
            self.TYPE_DICT = self.master_messages.TYPE_DICT

            self.etm_master_messages_patch()
            self.etm_slave_messages_patch()
            self.etm_chat_binding_patch()

        if hasattr(coordinator, "slaves") and coordinator.slaves['blueset.wechat']:
            self.channel_ews = coordinator.slaves['blueset.wechat']
            self.chats = self.channel_ews.chats
            self.flag = self.channel_ews.flag

            self.registered = self.channel_ews.bot.registered
            self._bot_send_msg = self.channel_ews._bot_send_msg
            self._bot_send_file = self.channel_ews._bot_send_file
            self._bot_send_image = self.channel_ews._bot_send_image
            self._bot_send_video = self.channel_ews._bot_send_video
            self.MAX_FILE_SIZE = self.channel_ews.MAX_FILE_SIZE

            self.wechat_unsupported_msg = self.channel_ews.slave_message.wechat_unsupported_msg
            self.wechat_shared_image_msg = self.channel_ews.slave_message.wechat_shared_image_msg
            self.wechat_shared_link_msg = self.channel_ews.slave_message.wechat_shared_link_msg
            self.wechat_raw_link_msg = self.channel_ews.slave_message.wechat_raw_link_msg
            self.wechat_text_msg = self.channel_ews.slave_message.wechat_text_msg
            self.UNSUPPORTED_MSG_PROMPT = self.channel_ews.slave_message.UNSUPPORTED_MSG_PROMPT

            self.ews_set_mark_as_read()
            self.ews_init_patch()
            self.ews_slave_message_patch()

        # self.logger.log(99, "[%s] init...", self.middleware_name)

    def etm_slave_messages_patch(self):
        self.slave_messages.generate_message_template = self.generate_message_template
        self.slave_messages.slave_message_video = self.slave_message_video
        self.slave_messages.slave_message_file = self.slave_message_file
        self.slave_messages.slave_message_image = self.slave_message_image
        self.slave_messages.get_slave_msg_dest = self.get_slave_msg_dest

    def etm_master_messages_patch(self):
        self.master_messages.DELETE_FLAG = self.channel.config.get('delete_flag', self.master_messages.DELETE_FLAG)
        self.DELETE_FLAG = self.master_messages.DELETE_FLAG
        self.master_messages.process_telegram_message = self.process_telegram_message

        self.bot.dispatcher.add_handler(CommandHandler('relate_group', self.relate_group))
        self.bot.dispatcher.add_handler(CommandHandler('release_group', self.release_group))

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
        user = self.updater.bot.getChatMember(message.chat.id, update.effective_user.id, 5)

        # message.text = f"[{message.from_user.username or message.from_user.first_name}]: {message.text}"

        return user.status not in ('administrator', 'creator')

    def ews_set_mark_as_read(self):
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

    def sent_by_master(self, message: EFBMsg) -> bool:
        author = message.author
        return author and author.module_id and author.module_id == 'blueset.telegram'

    def process_message(self, message: EFBMsg) -> Optional[EFBMsg]:
        """
        Process a message with middleware
        Args:
            message (:obj:`.EFBMsg`): Message object to process
        Returns:
            Optional[:obj:`.EFBMsg`]: Processed message or None if discarded.
        """

        # if self.sent_by_master(message):
        #     return message

        return message

    # efb_telegram_master/slave_message.py
    def generate_message_template(self, msg: EFBMsg, tg_chat, multi_slaves: bool) -> str:
        msg_prefix = ""  # For group member name
        if msg.chat.chat_type == ChatType.Group:
            self.logger.debug("[%s] Message is from a group. Sender: %s", msg.uid, msg.author)
            ### patch modified 👇 ###
            msg_prefix = self.get_display_name(msg.author)

        if tg_chat and not multi_slaves:  # if singly linked
            if msg_prefix:  # if group message
                msg_template = f"{msg_prefix}:"
            else:
                if msg.chat != msg.author:
                    ### patch modified 👇 ###
                    msg_template = "%s:" % self.get_display_name(msg.author)
                else:
                    msg_template = ""
        elif msg.chat.chat_type == ChatType.User:
            emoji_prefix = msg.chat.channel_emoji + Emoji.get_source_emoji(msg.chat.chat_type)
            ### patch modified 👇 ###
            name_prefix = self.get_display_name(msg.chat)
            if msg.chat != msg.author:
                ### patch modified 👇 ###
                name_prefix += ", %s" % self.get_display_name(msg.author)
            msg_template = f"{emoji_prefix} {name_prefix}:"
        elif msg.chat.chat_type == ChatType.Group:
            emoji_prefix = msg.chat.channel_emoji + Emoji.get_source_emoji(msg.chat.chat_type)
            ### patch modified 👇 ###
            name_prefix = self.get_display_name(msg.chat)
            msg_template = f"{emoji_prefix} {msg_prefix} [{name_prefix}]:"
        elif msg.chat.chat_type == ChatType.System:
            emoji_prefix = msg.chat.channel_emoji + Emoji.get_source_emoji(msg.chat.chat_type)
            ### patch modified 👇 ###
            name_prefix = self.get_display_name(msg.chat)
            msg_template = f"{emoji_prefix} {name_prefix}:"
        else:
            if msg.chat == msg.author:
                msg_template = f"\u2753 {msg.chat.long_name}:"
            else:
                msg_template = f"\u2753 {msg.author.long_name} ({msg.chat.display_name}):"
        return msg_template

    def get_display_name(self, chat: ETMChat) -> str:
        return chat.chat_name if not chat.chat_alias or chat.chat_alias in chat.chat_name \
            else (chat.chat_alias if chat.chat_name in chat.chat_alias else f"{chat.chat_alias} ({chat.chat_name})")

    # efb_telegram_master/slave_message.py
    def slave_message_video(self, msg: EFBMsg, tg_dest: TelegramChatID, msg_template: str, reactions: str,
                            old_msg_id: OldMsgID = None,
                            target_msg_id: Optional[TelegramMessageID] = None,
                            reply_markup: Optional[telegram.ReplyMarkup] = None,
                            silent: bool = False) -> telegram.Message:
        self.bot.send_chat_action(tg_dest, telegram.ChatAction.UPLOAD_VIDEO)
        ### patch modified start 👇 ###
        # if not msg.text:
        #     msg.text = self._("sent a video.")
        ### patch modified end 👆 ###
        try:
            if old_msg_id:
                if msg.edit_media:
                    assert msg.file is not None
                    self.bot.edit_message_media(chat_id=old_msg_id[0], message_id=old_msg_id[1], media=msg.file)
                return self.bot.edit_message_caption(chat_id=old_msg_id[0], message_id=old_msg_id[1],
                                                     prefix=msg_template, suffix=reactions, caption=msg.text)
            assert msg.file is not None
            return self.bot.send_video(tg_dest, msg.file, prefix=msg_template, suffix=reactions, caption=msg.text,
                                       reply_to_message_id=target_msg_id,
                                       reply_markup=reply_markup,
                                       disable_notification=silent)
        finally:
            if msg.file is not None:
                msg.file.close()

    # efb_telegram_master/slave_message.py
    def slave_message_file(self, msg: EFBMsg, tg_dest: TelegramChatID, msg_template: str, reactions: str,
                           old_msg_id: OldMsgID = None,
                           target_msg_id: Optional[TelegramMessageID] = None,
                           reply_markup: Optional[telegram.ReplyMarkup] = None,
                           silent: bool = False) -> telegram.Message:
        self.bot.send_chat_action(tg_dest, telegram.ChatAction.UPLOAD_DOCUMENT)

        if msg.filename is None and msg.path is not None:
            file_name = os.path.basename(msg.path)
        else:
            assert msg.filename is not None  # mypy compliance
            file_name = msg.filename

        # Telegram Bot API drops everything after `;` in filenames
        # Replace it with a space
        # Note: it also seems to strip off a lot of unicode punctuations
        file_name = file_name.replace(';', ' ')
        ### patch modified 👇 ###
        # msg.text = msg.text or self._("sent a file.")
        try:
            if old_msg_id:
                if msg.edit_media:
                    assert msg.file is not None
                    self.bot.edit_message_media(chat_id=old_msg_id[0], message_id=old_msg_id[1], media=msg.file)
                return self.bot.edit_message_caption(chat_id=old_msg_id[0], message_id=old_msg_id[1],
                                                     prefix=msg_template, suffix=reactions, caption=msg.text)
            assert msg.file is not None
            self.logger.debug("[%s] Uploading file %s (%s) as %s", msg.uid,
                              msg.file.name, msg.mime, file_name)
            return self.bot.send_document(tg_dest, msg.file,
                                          prefix=msg_template, suffix=reactions,
                                          caption=msg.text, filename=file_name,
                                          reply_to_message_id=target_msg_id,
                                          reply_markup=reply_markup,
                                          disable_notification=silent)
        finally:
            if msg.file is not None:
                msg.file.close()

    # efb_telegram_master/slave_message.py
    def slave_message_image(self, msg: EFBMsg, tg_dest: TelegramChatID, msg_template: str, reactions: str,
                            old_msg_id: OldMsgID = None,
                            target_msg_id: Optional[TelegramMessageID] = None,
                            reply_markup: Optional[telegram.ReplyMarkup] = None,
                            silent: bool = False) -> telegram.Message:
        self.bot.send_chat_action(tg_dest, telegram.ChatAction.UPLOAD_PHOTO)
        self.logger.debug("[%s] Message is of %s type; Path: %s; MIME: %s", msg.uid, msg.type, msg.path, msg.mime)
        if msg.path:
            self.logger.debug("[%s] Size of %s is %s.", msg.uid, msg.path, os.stat(msg.path).st_size)

        ### patch modified start 👇 ###
        # if not msg.text:
        #     msg.text = self._("sent a picture.")
        ### patch modified end 👆 ###
        try:
            if old_msg_id:
                if msg.edit_media:
                    self.bot.edit_message_media(chat_id=old_msg_id[0], message_id=old_msg_id[1], media=msg.file)
                return self.bot.edit_message_caption(chat_id=old_msg_id[0], message_id=old_msg_id[1],
                                                     prefix=msg_template, suffix=reactions, caption=msg.text)
            else:

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

                if send_as_file:
                    return self.bot.send_document(tg_dest, msg.file, prefix=msg_template, suffix=reactions,
                                                  caption=msg.text, filename=msg.filename,
                                                  reply_to_message_id=target_msg_id,
                                                  reply_markup=reply_markup,
                                                  disable_notification=silent)
                else:
                    try:
                        return self.bot.send_photo(tg_dest, msg.file, prefix=msg_template, suffix=reactions,
                                                   caption=msg.text,
                                                   reply_to_message_id=target_msg_id,
                                                   reply_markup=reply_markup,
                                                   disable_notification=silent)
                    except telegram.error.BadRequest as e:
                        self.logger.error('[%s] Failed to send it as image, sending as document. Reason: %s',
                                          msg.uid, e)
                        return self.bot.send_document(tg_dest, msg.file, prefix=msg_template, suffix=reactions,
                                                      caption=msg.text, filename=msg.filename,
                                                      reply_to_message_id=target_msg_id,
                                                      reply_markup=reply_markup,
                                                      disable_notification=silent)
        finally:
            if msg.file:
                msg.file.close()

    # efb_telegram_master/slave_message.py
    def get_slave_msg_dest(self, msg: EFBMsg) -> Tuple[str, Optional[TelegramChatID]]:
        """Get the Telegram destination of a message with its header.

        Returns:
            msg_template (str): header of the message.
            tg_dest (Optional[str]): Telegram destination chat, None if muted.
        """
        xid = msg.uid
        msg.author = self.chat_manager.update_chat_obj(msg.author)
        msg.chat = self.chat_manager.update_chat_obj(msg.chat)
        chat_uid = utils.chat_id_to_str(chat=msg.chat)
        tg_chats = self.db.get_chat_assoc(slave_uid=chat_uid)
        tg_chat = None

        if tg_chats:
            tg_chat = tg_chats[0]
        self.logger.debug("[%s] The message should deliver to %s", xid, tg_chat)

        ### patch modified start 👇 ###
        # 如果没有绑定，判断同名的tg群组，自动尝试关联
        if not tg_chat:
            t_chat = ETMChat(chat=msg.chat, db=self.db)
            tg_mp = self.channel.config.get('tg_mp')

            master_name = f"{t_chat.chat_alias or t_chat.chat_name}"
            tg_group = self.tgdb.get_tg_groups(master_name=master_name)

            if tg_group is not None:
                auto_detect_tg_dest = tg_group.master_id
                multi_slaves = bool(tg_group.multi_slaves)
                tg_chat = utils.chat_id_to_str(self.channel.channel_id, auto_detect_tg_dest)
                t_chat.link(self.channel.channel_id, auto_detect_tg_dest, multi_slaves)

            elif t_chat.vendor_specific.get('is_mp', False) and tg_mp:
                tg_chat = utils.chat_id_to_str(self.channel.channel_id, tg_mp)
                t_chat.link(self.channel.channel_id, tg_mp, True)

        else:
            # 已绑定的，判断是否有更新名称，并且在tg_groups内有映射，则更新映射新的微信名称
            if msg.author and msg.author.chat_type == ChatType.System:
                self.mod_tit_pattern = re.compile(r'修改群名为“(.*)”')
                result = self.mod_tit_pattern.findall(msg.text)
                if len(result) > 0:
                    new_tit = result[0]
                    self.tgdb.update_tg_groups(int(utils.chat_id_str_to_id(tg_chat)[1]), new_tit)
        ### patch modified end 👆 ###

        multi_slaves = False
        if tg_chat:
            slaves = self.db.get_chat_assoc(master_uid=tg_chat)
            if slaves and len(slaves) > 1:
                multi_slaves = True
                self.logger.debug("[%s] Sender is linked with other chats in a Telegram group.", xid)
        self.logger.debug("[%s] Message is in chat %s", xid, msg.chat)

        # Generate chat text template & Decide type target
        tg_dest = self.channel.config['admins'][0]

        if tg_chat:  # if this chat is linked
            tg_dest = int(utils.chat_id_str_to_id(tg_chat)[1])

        msg_template = self.generate_message_template(msg, tg_chat, multi_slaves)
        self.logger.debug("[%s] Message is sent to Telegram chat %s, with header \"%s\".",
                          xid, tg_dest, msg_template)

        if self.chat_dest_cache.get(tg_dest) != chat_uid:
            self.chat_dest_cache.remove(tg_dest)

        return msg_template, tg_dest

    # efb_telegram_master/chat_binding.py
    def update_group_info(self, update: Update, context: CallbackContext):
        """
        Update the title and profile picture of singly-linked Telegram group
        according to the linked remote chat.

        Triggered by ``/update_info`` command.
        """
        if update.effective_chat.type == Chat.PRIVATE:
            return self.bot.reply_error(update, self._('Send /update_info to a group where this bot is a group admin '
                                                       'to update group title, description and profile picture.'))
        forwarded_from_chat = update.effective_message.forward_from_chat
        if forwarded_from_chat and forwarded_from_chat.type == Chat.CHANNEL:
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
            chat_title=f"{chat.chat_alias or chat.chat_name}"
            self.tgdb.add_tg_groups(master_id=tg_chat, master_name=chat_title)
            self.bot.set_chat_title(tg_chat, self.truncate_ellipsis(chat_title, self.MAX_LEN_CHAT_TITLE))
            ### patch modified end 👆 ###

            # Update remote group members list to Telegram group description if available
            # TODO: Add chat bio too when it’s available in the framework
            if chat.members:
                # TRANSLATORS: Separator between group members in a Telegram group description generated by /update_info
                desc = self._(", ").join(i.long_name for i in chat.members)
                desc = self.ngettext("{count} group member: {list}",
                                     "{count} group members: {list}",
                                     len(chat.members)).format(
                    count=len(chat.members), list=desc
                )
                try:
                    self.bot.set_chat_description(
                        tg_chat, self.truncate_ellipsis(desc, self.MAX_LEN_CHAT_DESC))
                except TelegramError as e:  # description is not updated
                    ### patch modified 👇 ###
                    # self.logger.exception("Exception occurred while trying to update chat description: %s", e)
                    pass

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

        channel_id, chat_uid = utils.chat_id_str_to_id(msg_log.slave_origin_uid)
        try:
            channel = coordinator.slaves[channel_id]
            chat = channel.get_chat(chat_uid)
            if chat is None:
                raise EFBChatNotFound()
            chat = ETMChat(chat=chat, db=self.db)
            # self.bot.set_chat_title(tg_chat, chat.chat_title)
            chat_title=f"{chat.chat_alias or chat.chat_name}"
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

        channel_id, chat_uid = utils.chat_id_str_to_id(msg_log.slave_origin_uid)
        try:
            channel = coordinator.slaves[channel_id]
            chat = channel.get_chat(chat_uid)
            if chat is None:
                raise EFBChatNotFound()
            chat = ETMChat(chat=chat, db=self.db)

            chat_title=f"{chat.chat_alias or chat.chat_name}"
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
    def process_telegram_message(self, update: Update, context: CallbackContext,
                                 channel_id: Optional[ModuleID] = None,
                                 chat_id: Optional[ChatID] = None,
                                 target_msg: Optional[utils.TgChatMsgIDStr] = None):
        """
        Process messages came from Telegram.

        Args:
            update: Telegram message update
            context: PTB update context
            channel_id: Slave channel ID if specified
            chat_id: Slave chat ID if specified
            target_msg: Target slave message if specified
        """
        target: Optional[EFBChannelChatIDStr] = None
        target_channel: Optional[ModuleID] = None
        target_log: Optional['MsgLog'] = None
        # Message ID for logging
        message_id = utils.message_id_to_str(update=update)

        multi_slaves: bool = False
        destination: Optional[EFBChannelChatIDStr] = None
        slave_msg: Optional[EFBMsg] = None

        message: telegram.Message = update.effective_message

        edited = bool(update.edited_message or update.edited_channel_post)
        self.logger.debug('[%s] Message is edited: %s, %s',
                          message_id, edited, message.edit_date)

        private_chat = update.effective_chat.type == telegram.Chat.PRIVATE

        if not private_chat:  # from group
            linked_chats = self.db.get_chat_assoc(master_uid=utils.chat_id_to_str(
                self.channel_id, update.effective_chat.id))
            if len(linked_chats) == 1:
                destination = linked_chats[0]
            elif len(linked_chats) > 1:
                multi_slaves = True

        reply_to = bool(getattr(message, "reply_to_message", None))

        # Process predefined target (slave) chat.
        cached_dest = self.chat_dest_cache.get(message.chat.id)
        if channel_id and chat_id:
            destination = utils.chat_id_to_str(channel_id, chat_id)
            # TODO: what is going on here?
            if target_msg is not None:
                target_log = self.db.get_msg_log(master_msg_id=target_msg)
                if target_log:
                    target = target_log.slave_origin_uid
                    if target is not None:
                        target_channel, target_uid, _ = utils.chat_id_str_to_id(target)
                else:
                    return self.bot.reply_error(update,
                                                self._("Message is not found in ETM database. "
                                                       "Please try with another message. (UC07)"))
        elif private_chat:
            if reply_to:
                dest_msg = self.db.get_msg_log(master_msg_id=utils.message_id_to_str(
                    message.reply_to_message.chat.id,
                    message.reply_to_message.message_id))
                if dest_msg:
                    destination = dest_msg.slave_origin_uid
                    self.chat_dest_cache.set(message.chat.id, dest_msg.slave_origin_uid)
                else:
                    return self.bot.reply_error(update,
                                                self._("Message is not found in ETM database. "
                                                       "Please try with another one. (UC03)"))
            elif cached_dest:
                destination = cached_dest
                self._send_cached_chat_warning(update, message.chat.id, cached_dest)
            else:
                return self.bot.reply_error(update,
                                            self._("Please reply to an incoming message. (UC04)"))
        else:  # group chat
            ### patch modified start 👇 ###
            # if reply_to:
            #     # 回复其他人，不处理
            #     if message.reply_to_message.from_user.id != self.bot.me.id:
            #         self.logger.debug("Message is not reply to the bot: %s", message.to_dict())
            #         return
            ### patch modified end 👆 ###
            if multi_slaves:
                if reply_to:
                    dest_msg = self.db.get_msg_log(master_msg_id=utils.message_id_to_str(
                        message.reply_to_message.chat.id,
                        message.reply_to_message.message_id))
                    if dest_msg:
                        destination = dest_msg.slave_origin_uid
                        assert destination is not None
                        self.chat_dest_cache.set(message.chat.id, destination)
                    else:
                        return self.bot.reply_error(update,
                                                    self._("Message is not found in ETM database. "
                                                           "Please try with another one. (UC05)"))
                elif cached_dest:
                    destination = cached_dest
                    self._send_cached_chat_warning(update, message.chat.id, cached_dest)
                else:
                    return self.bot.reply_error(update,
                                                self._("This group is linked to multiple remote chats. "
                                                       "Please reply to an incoming message. "
                                                       "To unlink all remote chats, please send /unlink_all . (UC06)"))
            elif destination:
                if reply_to:
                    target_log = \
                        self.db.get_msg_log(master_msg_id=utils.message_id_to_str(
                            message.reply_to_message.chat.id,
                            message.reply_to_message.message_id))
                    if target_log:
                        target = target_log.slave_origin_uid
                        if target is not None:
                            target_channel, target_uid, _ = utils.chat_id_str_to_id(target)
                    else:
                        return self.bot.reply_error(update,
                                                    self._("Message is not found in ETM database. "
                                                           "Please try with another message. (UC07)"))
            else:
                return self.bot.reply_error(update,
                                            self._("This group is not linked to any chat. (UC06)"))

        self.logger.debug("[%s] Telegram received. From private chat: %s; Group has multiple linked chats: %s; "
                          "Message replied to another message: %s", message_id, private_chat, multi_slaves, reply_to)
        self.logger.debug("[%s] Destination chat = %s", message_id, destination)
        assert destination is not None
        channel, uid, gid = utils.chat_id_str_to_id(destination)
        if channel not in coordinator.slaves:
            return self.bot.reply_error(update, self._("Internal error: Slave channel “{0}” not found.").format(channel))

        m = ETMMsg()
        log_message = True
        try:
            m.uid = MessageID(message_id)
            m.put_telegram_file(message)
            mtype = m.type_telegram
            # Chat and author related stuff
            m.chat = self.chat_manager.get_chat(channel, uid, gid, build_dummy=True)
            if m.chat.chat_type == ChatType.Group:
                m.author = self.chat_manager.get_self(m.chat.chat_uid)
            else:
                m.author = self.chat_manager.self

            m.deliver_to = coordinator.slaves[channel]
            ### patch modified 👇 ###
            m.is_forward = bool(getattr(message, "forward_from", None))
            if target and target_log is not None and target_channel == channel:
                trgt_msg: ETMMsg = target_log.build_etm_msg(self.chat_manager, recur=False)
                trgt_msg.target = None
                m.target = trgt_msg

                self.logger.debug("[%s] This message replies to another message of the same channel.\n"
                                  "Chat ID: %s; Message ID: %s.", message_id, trgt_msg.chat.chat_uid, trgt_msg.uid)
            # Type specific stuff
            self.logger.debug("[%s] Message type from Telegram: %s", message_id, mtype)

            if self.TYPE_DICT.get(mtype, None):
                m.type = self.TYPE_DICT[mtype]
                self.logger.debug("[%s] EFB message type: %s", message_id, mtype)
            else:
                self.logger.info("[%s] Message type %s is not supported by ETM", message_id, mtype)
                raise EFBMessageTypeNotSupported(self._("Message type {} is not supported by ETM.").format(mtype.name))

            if m.type not in coordinator.slaves[channel].supported_message_types:
                self.logger.info("[%s] Message type %s is not supported by channel %s",
                                 message_id, m.type.name, channel)
                raise EFBMessageTypeNotSupported(self._("Message type {0} is not supported by channel {1}.")
                                                 .format(m.type.name, coordinator.slaves[channel].channel_name))

            # Parse message text and caption to markdown
            msg_md_text = message.text and message.text_markdown
            if msg_md_text and msg_md_text == escape_markdown(message.text):
                msg_md_text = message.text
            msg_md_text = msg_md_text or ""

            msg_md_caption = message.caption and message.caption_markdown
            if msg_md_caption and msg_md_caption == escape_markdown(message.caption):
                msg_md_caption = message.caption
            msg_md_caption = msg_md_caption or ""

            # Flag for edited message
            if edited:
                m.edit = True
                # Telegram Bot API did not provide any info about whether media is edited,
                # so ``edit_media`` should be always flagged up to prevent unwanted issue.
                m.edit_media = True
                text = msg_md_text or msg_md_caption
                msg_log = self.db.get_msg_log(master_msg_id=utils.message_id_to_str(update=update))
                if not msg_log or msg_log.slave_message_id == self.db.FAIL_FLAG:
                    raise EFBMessageNotFound()
                m.uid = msg_log.slave_message_id
                if text.startswith(self.DELETE_FLAG):
                    coordinator.send_status(EFBMessageRemoval(
                        source_channel=self.channel,
                        destination_channel=coordinator.slaves[channel],
                        message=m
                    ))
                    if not self.channel.flag('prevent_message_removal'):
                        try:
                            message.delete()
                        except telegram.TelegramError:
                            message.reply_text(self._("Message is removed in remote chat."))
                    else:
                        message.reply_text(self._("Message is removed in remote chat."))
                    log_message = False
                    return
                self.logger.debug('[%s] Message is edited (%s)', m.uid, m.edit)

            ### patch modified start 👇 ###
            # 以rm开头回复来撤回自己发送的消息
            if reply_to and message.reply_to_message.from_user.id == message.from_user.id and msg_md_text.startswith(self.DELETE_FLAG):
                m.edit = True
                m.edit_media = True
                msg_log = self.db.get_msg_log(master_msg_id=utils.message_id_to_str(
                            message.reply_to_message.chat.id,
                            message.reply_to_message.message_id))
                if not msg_log or msg_log == self.db.FAIL_FLAG:
                    raise EFBMessageNotFound()
                m.uid = msg_log.slave_message_id
                coordinator.send_status(EFBMessageRemoval(
                    source_channel=self.channel,
                    destination_channel=coordinator.slaves[channel],
                    message=m
                ))
                if not self.channel.flag('prevent_message_removal'):
                    try:
                        message.delete()
                    except telegram.TelegramError:
                        message.reply_text(self._("Message removed in remote chat."))
                else:
                    message.reply_text(self._("Message removed in remote chat."))
                self.db.delete_msg_log(master_msg_id=utils.message_id_to_str(
                        message.reply_to_message.chat.id,
                        message.reply_to_message.message_id))
                log_message = False
                return
            ### patch modified end 👆 ###

            # Enclose message as an EFBMsg object by message type.
            if mtype == TGMsgType.Text:
                m.text = msg_md_text
            elif mtype == TGMsgType.Photo:
                m.text = msg_md_caption
                m.mime = "image/jpeg"
                self._check_file_download(message.photo[-1])
            elif mtype in (TGMsgType.Sticker, TGMsgType.AnimatedSticker):
                # Convert WebP to the more common PNG
                m.text = ""
                self._check_file_download(message.sticker)
            elif mtype == TGMsgType.Animation:
                m.text = ""
                self.logger.debug("[%s] Telegram message is a \"Telegram GIF\".", message_id)
                m.filename = getattr(message.document, "file_name", None) or None
                m.mime = message.document.mime_type or m.mime
            elif mtype == TGMsgType.Document:
                m.text = msg_md_caption
                self.logger.debug("[%s] Telegram message type is document.", message_id)
                m.filename = getattr(message.document, "file_name", None) or None
                m.mime = message.document.mime_type
                self._check_file_download(message.document)
            elif mtype == TGMsgType.Video:
                m.text = msg_md_caption
                m.mime = message.video.mime_type
                self._check_file_download(message.video)
            elif mtype == TGMsgType.Audio:
                m.text = "%s - %s\n%s" % (
                    message.audio.title, message.audio.performer, msg_md_caption)
                m.mime = message.audio.mime_type
                self._check_file_download(message.audio)
            elif mtype == TGMsgType.Voice:
                m.text = msg_md_caption
                m.mime = message.voice.mime_type
                self._check_file_download(message.voice)
            elif mtype == TGMsgType.Location:
                # TRANSLATORS: Message body text for location messages.
                m.text = self._("Location")
                m.attributes = EFBMsgLocationAttribute(
                    message.location.latitude,
                    message.location.longitude
                )
            elif mtype == TGMsgType.Venue:
                m.text = message.location.title + "\n" + message.location.adderss
                m.attributes = EFBMsgLocationAttribute(
                    message.venue.location.latitude,
                    message.venue.location.longitude
                )
            elif mtype == TGMsgType.Contact:
                contact: telegram.Contact = message.contact
                m.text = self._("Shared a contact: {first_name} {last_name}\n{phone_number}").format(
                    first_name=contact.first_name, last_name=contact.last_name, phone_number=contact.phone_number
                )
            else:
                raise EFBMessageTypeNotSupported(self._("Message type {0} is not supported.").format(mtype))

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
            self.bot.reply_error(update, self._("Message editing is not supported.\n\n{exception!s}".format(exception=e)))
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
        # This method is not wrapped by wechat_msg_meta decorator, thus no need to return EFBMsg object.
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
                    else:
                        # Unidentified message type
                        self.logger.error("[%s] Identified unsupported sharing message type. Raw message: %s",
                                          msg.id, msg.raw)
                        raise KeyError()
                except (TypeError, KeyError, ValueError, ETree.ParseError):
                    return self.wechat_unsupported_msg(msg)
        if self.channel_ews.flag("first_link_only"):
            links = links[:1]

        for i in links:
            self.wechat_raw_link_msg(msg, i.title, i.summary, i.cover, i.url)

    # efb_wechat_slave/__init__.py
    def send_message(self, msg: EFBMsg) -> EFBMsg:
        """Send a message to WeChat.
        Supports text, image, sticker, and file.

        Args:
            msg (channel.EFBMsg): Message Object to be sent.

        Returns:
            This method returns nothing.

        Raises:
            EFBMessageTypeNotSupported: Raised when message type is not supported by the channel.
        """
        chat: wxpy.Chat = self.chats.get_wxpy_chat_by_uid(msg.chat.chat_uid)

        # List of "SentMessage" response for all messages sent
        r: List[wxpy.SentMessage] = []
        self.logger.info("[%s] Sending message to WeChat:\n"
                         "uid: %s\n"
                         "UserName: %s\n"
                         "NickName: %s\n"
                         "Type: %s\n"
                         "Text: %s",
                         msg.uid,
                         msg.chat.chat_uid, chat.user_name, chat.name, msg.type, msg.text)

        try:
            chat.mark_as_read()
        except wxpy.ResponseError as e:
            self.logger.exception("[%s] Error occurred while marking chat as read. (%s)", msg.uid, e)

        send_text_only = False
        self.logger.debug('[%s] Is edited: %s', msg.uid, msg.edit)
        if msg.edit:
            if self.flag('delete_on_edit'):
                msg_ids = json.loads(msg.uid)
                if not msg.edit_media:
                    # Treat message as text message to prevent resend of media
                    msg_ids = msg_ids[1:]
                    send_text_only = True
                failed = 0
                for i in msg_ids:
                    try:
                        ews_utils.message_to_dummy_message(i, self).recall()
                    except wxpy.ResponseError as e:
                        self.logger.error("[%s] Trying to recall message but failed: %s", msg.uid, e)
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
            if isinstance(msg.target, EFBMsg):
                max_length = self.flag("max_quote_length")
                qt_txt = msg.target.text or msg.target.type.name
                if max_length > 0:
                    if len(qt_txt) >= max_length:
                        tgt_text = qt_txt[:max_length]
                        tgt_text += "…"
                    else:
                        tgt_text = qt_txt
                    tgt_text = "「%s」" % tgt_text
                elif max_length < 0:
                    tgt_text = "「%s」" % qt_txt
                else:
                    tgt_text = ""
                if isinstance(chat, wxpy.Group) and not msg.target.author.is_self:
                    tgt_alias = "@%s\u2005 " % msg.target.author.display_name
                else:
                    tgt_alias = ""
                msg.text = "%s%s\n\n%s" % (tgt_alias, tgt_text, msg.text)
            r.append(self._bot_send_msg(chat, msg.text))
            self.logger.debug('[%s] Sent as a text message. %s', msg.uid, msg.text)
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
                            mask = Image.eval(alpha, lambda a: 255 if a <= 128 else 0)
                        except IndexError:
                            mask = Image.eval(img.split()[0], lambda a: 0)
                        img = img.convert('RGB').convert('P', palette=Image.ADAPTIVE, colors=255)
                        img.paste(255, mask)
                        img.save(f, transparency=255)
                        msg.path = f.name
                        self.logger.debug('[%s] Image converted from %s to GIF', msg.uid, msg.mime)
                        file.close()
                        f.seek(0)
                        if os.fstat(f.fileno()).st_size > self.MAX_FILE_SIZE:
                            raise EFBMessageError(self._("Image size is too large. (IS02)"))
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
                        msg.path = f.name
                        self.logger.debug('[%s] Image converted from %s to JPEG', msg.uid, msg.mime)
                        file.close()
                        f.seek(0)
                        if os.fstat(f.fileno()).st_size > self.MAX_FILE_SIZE:
                            raise EFBMessageError(self._("Image size is too large. (IS02)"))
                        r.append(self._bot_send_image(chat, f.name, f))
                    finally:
                        if not file.closed:
                            file.close()
            else:
                try:
                    if os.fstat(file.fileno()).st_size > self.MAX_FILE_SIZE:
                        raise EFBMessageError(self._("Image size is too large. (IS01)"))
                    self.logger.debug("[%s] Sending %s (image) to WeChat.", msg.uid, msg.path)
                    r.append(self._bot_send_image(chat, msg.path, file))
                finally:
                    if not file.closed:
                        file.close()
            ### patch modified 👇 ###
            if msg.text and not msg.is_forward:
                r.append(self._bot_send_msg(chat, msg.text))
        elif msg.type in (MsgType.File, MsgType.Audio):
            self.logger.info("[%s] Sending %s to WeChat\nFileName: %s\nPath: %s\nFilename: %s",
                             msg.uid, msg.type, msg.text, msg.path, msg.filename)
            r.append(self._bot_send_file(chat, msg.filename, file=msg.file))
            ### patch modified 👇 ###
            if msg.text and not msg.is_forward:
                self._bot_send_msg(chat, msg.text)
            msg.file.close()
        elif msg.type == MsgType.Video:
            self.logger.info("[%s] Sending video to WeChat\nFileName: %s\nPath: %s", msg.uid, msg.text, msg.path)
            r.append(self._bot_send_video(chat, msg.path, file=msg.file))
            ### patch modified 👇 ###
            if msg.text and not msg.is_forward:
                r.append(self._bot_send_msg(chat, msg.text))
            msg.file.close()
        else:
            raise EFBMessageTypeNotSupported()

        msg.uid = ews_utils.generate_message_uid(r)
        self.logger.debug('WeChat message is assigned with unique ID: %s', msg.uid)
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

    @staticmethod
    def get_node_text(root: Element, path: str, fallback: str) -> str:
        node = root.find(path)
        if node is not None:
            return node.text or fallback
        return fallback
