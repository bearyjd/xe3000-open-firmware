# SPDX-License-Identifier: GPL-2.0-only
# Placeholder package for the XE3000 (Puli) battery/fan MCU helper.
# No vendor code or binaries: the protocol is filled in only after the stock-firmware findings are reviewed.
include $(TOPDIR)/rules.mk

PKG_NAME:=gl-puli-mcu
PKG_VERSION:=0.0.1
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/gl-puli-mcu
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=GL-XE3000 battery/fan MCU helper (placeholder)
  DEPENDS:=@TARGET_mediatek_filogic
endef

define Package/gl-puli-mcu/description
  Placeholder. Selected for the glinet_gl-xe3000 device only by recipe/config/xe3000.config.
endef

define Build/Compile
endef

define Package/gl-puli-mcu/install
	$(INSTALL_DIR) $(1)/usr/share/xe3000
	echo "placeholder" > $(1)/usr/share/xe3000/gl-puli-mcu.txt
endef

$(eval $(call BuildPackage,gl-puli-mcu))
