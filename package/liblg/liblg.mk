# See libss7 for reference 
# TODO: Install
LIBLG_VERSION = 746f0df43774175090b93abcc860b6733eefc09b
LIBLG_SITE = $(call github,joan2937,lg,$(LIBLG_VERSION))
LIBLG_INSTALL_STAGING = YES
LIBLG_INSTALL_TARGET = YES

LIBLG_MAKE_OPTS = \
        CC=$(TARGET_CC) \
        CFLAGS_EXTRA="$(TARGET_CFLAGS)" \
        LDFLAGS_EXTRA="$(TARGET_LDFLAGS)" \
        PREFIX=/usr

define LIBLG_BUILD_CMDS
     $(TARGET_MAKE_ENV) $(MAKE) -C $(@D) $(LIBLG_MAKE_OPTS)
endef

define LIBLG_INSTALL_STAGING_CMDS
	$(INSTALL) -D -m 0644 $(@D)/lgpio.h $(STAGING_DIR)/usr/include/lgpio.h
	$(INSTALL) -D -m 0644 $(@D)/rgpio.h $(STAGING_DIR)/usr/include/rgpio.h
	$(INSTALL) -D -m 0644 $(@D)/liblgpio.so* $(STAGING_DIR)/usr/lib/
	$(INSTALL) -D -m 0644 $(@D)/librgpio.so* $(STAGING_DIR)/usr/lib/
endef

define LIBLG_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0644 $(@D)/liblgpio.so* $(TARGET_DIR)/usr/lib/
	$(INSTALL) -D -m 0644 $(@D)/librgpio.so* $(TARGET_DIR)/usr/lib/
endef

# REMOVE Comments:
#	install -m 0644 lgpio.h                  $(DESTDIR)$(includedir)
#	install -m 0644 rgpio.h                  $(DESTDIR)$(includedir)

#	install -m 0755 liblgpio.so.$(SOVERSION) $(DESTDIR)$(libdir)
#	install -m 0755 librgpio.so.$(SOVERSION) $(DESTDIR)$(libdir)
#	@cd $(DESTDIR)$(libdir) && ln -fs liblgpio.so.$(SOVERSION) liblgpio.so
#	@cd $(DESTDIR)$(libdir) && ln -fs librgpio.so.$(SOVERSION) librgpio.so

#define LIBSS7_INSTALL_STAGING_CMDS
#	$(call LIBSS7_INSTALL_A,$(STAGING_DIR))
#	$(call LIBSS7_INSTALL_SO,$(STAGING_DIR))
#	$(INSTALL) -D -m 0644 $(@D)/libss7.h $(STAGING_DIR)/usr/include/libss7.h
#endef

#define LIBSS7_INSTALL_TARGET_CMDS
#	$(foreach u,$(LIBSS7_UTILS),\
#		$(INSTALL) -D -m 0755 $(@D)/$(u) $(TARGET_DIR)/usr/sbin/$(u)$(sep))
#	$(call LIBSS7_INSTALL_SO,$(TARGET_DIR))
#endef

define LIBLG_CLEAN_CMDS
#        $(MAKE) $(LIBLG_MAKE_OPTS) -C $(@D) clean
endef

$(eval $(generic-package))
