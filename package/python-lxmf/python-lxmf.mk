################################################################################
#
# python-lxmf
#
# https://pypi.org/project/lxmf/
# https://files.pythonhosted.org/packages/99/1b/9311b5208783164f357c0d851a1ba28acc0d69b0d6d2a3352669cf62d509/lxmf-0.4.4.tar.gz
# https://files.pythonhosted.org/packages/01/9c/90ebaa7d1a6bb12cff37506634c1421d078facd967cd487e59588433adf7/lxmf-0.5.3.tar.gz
################################################################################

PYTHON_LXMF_VERSION = 0.5.3
PYTHON_LXMF_SOURCE = lxmf-$(PYTHON_LXMF_VERSION).tar.gz
PYTHON_LXMF_SITE = https://files.pythonhosted.org/packages/01/9c/90ebaa7d1a6bb12cff37506634c1421d078facd967cd487e59588433adf7
PYTHON_LXMF_LICENSE = MIT
PYTHON_LXMF_LICENSE_FILES = LICENSE-PSF LICENSE
PYTHON_LXMF_SETUP_TYPE = setuptools
# This is a runtime dependency, but we don't have the concept of
# runtime dependencies for host packages.

$(eval $(python-package))
