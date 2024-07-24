EPAPERC_VERSION = 968f4c0bcc6fbd9653fc13a903bcae984387c70a
EPAPERC_SITE = $(call github,resiliencetheatre,epaperc,$(EPAPERC_VERSION))
EPAPERC_PREFIX = $(TARGET_DIR)/usr
EPAPERC_LICENSE = gplv3
EPAPERC_DEPENDENCIES = liblg

define EPAPERC_BUILD_CMDS
     $(MAKE) $(TARGET_CONFIGURE_OPTS) -C $(@D) EPD=epd2in13V3
endef

define EPAPERC_INSTALL_TARGET_CMDS
        (cd $(@D); cp edgemap-ui $(EPAPERC_PREFIX)/bin)
endef

define EPAPERC_CLEAN_CMDS
        $(MAKE) $(EPAPERC_MAKE_OPTS) -C $(@D) clean
endef

$(eval $(generic-package))
