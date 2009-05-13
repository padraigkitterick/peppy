#! /usr/bin/env python
import os.path
from distutils.core import setup

classifiers = """\
Development Status :: 4 - Beta
Environment :: Console
Intended Audience :: System Administrators
License :: OSI Approved :: GNU General Public License (GPL)
Natural Language :: English
Programming Language :: Python
Topic :: Security
Topic :: Security :: Cryptography
Operating System :: OS Independent

"""
setup(name="peppy",
      version="1.0",
      classifiers = filter(None, classifiers.split("\n")),
      description="Python implementation of Perfect Paper Passwords (PPP)",
      author="Padraig Kitterick",
      author_email="info@padraigkitterick.com",
      url="http://www.padraigkitterick.com/code/",
      license="GNU GPL",
      packages = ["peppy"],
      scripts=[os.path.join('scripts','peppy')],
      )
