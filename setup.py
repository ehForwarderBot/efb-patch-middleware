import sys
import os
from setuptools import setup, find_packages

if sys.version_info < (3, 6):
    raise Exception(
        "Python 3.6 or higher is required. Your version is %s." % sys.version)

version_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            'efb_patch_middleware/__version__.py')

__version__ = ""
exec(open(version_path).read())

long_description = open('README.md', encoding="utf-8").read()

setup(
    name='efb-patch-middleware',
    packages=find_packages(
        exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    version=__version__,
    description='Patch middleware for EH Forwarder Bot, enhance functions.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='WolfSilver',
    author_email='aexou@outlook.com',
    url='https://github.com/efb-middleware/patch',
    license='AGPLv3+',
    include_package_data=True,
    python_requires='>=3.6',
    keywords=['ehforwarderbot', 'EH Forwarder Bot', 'EH Forwarder Bot Middleware', 'Patch'],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Communications :: Chat",
        "Topic :: Utilities"
    ],
    install_requires=[
        "ehforwarderbot",
        "efb_telegram_master",
        "efb_wechat_slave",
        "python-telegram-bot",
        "peewee",
        "PyYaml",
        "Pillow",
    ],
    entry_points={
        "ehforwarderbot.middleware": "patch.PatchMiddleware = efb_patch_middleware:PatchMiddleware"
    }
)
