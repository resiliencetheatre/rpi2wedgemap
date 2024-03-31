################################################################################
#
# python-epdlibrary
# 
################################################################################

PYTHON_EPDLIBRARY_VERSION = 0.2.3
PYTHON_EPDLIBRARY_SOURCE = epd-library-$(PYTHON_EPDLIBRARY_VERSION).tar.gz
PYTHON_EPDLIBRARY_SITE = https://files.pythonhosted.org/packages/a0/76/41512d9d14704b8d175b8ecccde23c0df626d9e0612e58841fad22749376
PYTHON_EPDLIBRARY_SETUP_TYPE = setuptools
PYTHON_EPDLIBRARY_LICENSE = Python Software Foundation License
PYTHON_EPDLIBRARY_LICENSE_FILES = LICENSE.txt doc/source/license.rst

$(eval $(python-package))
