#! /usr/bin/env python
from distutils.core import setup

classifiers = """\
Development Status :: 4 - Beta
Environment :: Console
Intended Audience :: System Administrators
License :: OSI Approved :: GNU General Public License (GPL)
Natural Language :: English
Programming Language :: Python
Programming Language :: C
Topic :: Security
Topic :: Security :: Cryptography
Topic :: Utilities
Operating System :: OS Independent

"""
setup(name="peppy",
      version="1.0",
      classifiers = filter(None, classifiers.split("\n")),
      description="Python implementation of Perfect Paper Passwords (PPP)",
      author="Padraig Kitterick",
      author_email="p.kitterick@psych.york.ac.uk",
      url="http://www.padraigkitterick.com/code/ppp/",
      license="GNU GPL",
      packages = ["peppy"],
      ext_modules=[Extension('peppy._aes',
                             sources=[os.path.join('peppy', '_aes.c')],
                             )],
      scripts=[os.path.join('scripts','peppy')],
      )
