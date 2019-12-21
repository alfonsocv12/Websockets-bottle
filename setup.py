import sys
from setuptools import setup

if sys.version_info < (3, 0):
     raise NotImplementedError("Sorry, you need at least Python 2.7 or Python 3.4+ to use bottle.")

import matcher

setup(name='websockets-router',
    version=matcher.__version__,
    description='Router for your websocket Application',
    author=matcher.__author__,
    py_modules=['matcher'],
    scripts=['matcher.py'],
    license='MIT',
    platforms='any',
    classifiers=['Development Status :: 4 - Beta',
                   "Operating System :: OS Independent",
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: MIT License',
                   'Topic :: Software Development :: Libraries :: Application Frameworks',
                   'Programming Language :: Python :: 3',
                   'Programming Language :: Python :: 3.4',
                   'Programming Language :: Python :: 3.5',
                   'Programming Language :: Python :: 3.6',
                   'Programming Language :: Python :: 3.7',
                   ],
)
