 #
 #  Copyright (C) 2014-2020 Amlogic, Inc. All rights reserved.
 #
 #  All information contained herein is Amlogic confidential.
 #
 #  This software is provided to you pursuant to Software License Agreement
 #  (SLA) with Amlogic Inc ("Amlogic"). This software may be used
 #  only in accordance with the terms of this agreement.
 #
 #  Redistribution and use in source and binary forms, with or without
 #  modification is strictly prohibited without prior written permission from
 #  Amlogic.
 #
 #  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 #  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 #  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 #  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 #  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 #  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 #  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 #  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 #  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 #  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 #  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 #

TOP := $(shell pwd)/..

export ATH_TOPDIR=$(TOP)
export INSTALL_ROOT=$(TOP)/rootfs-x86-android.build

export IF_TYPE ?= SDIO

ifneq ($(M),)
QCACLD := $(subst AIO/build,AIO/drivers/qcacld-new,$(M))
endif

export QCACLD

export CONFIG_LINUX_QCMBR=y
export CONFIG_NON_QC_PLATFORM=y
export CONFIG_WLAN_THERMAL_SHUTDOWN=0

ifeq ($(IF_TYPE),PCIE)
    export CONFIG_ROME_IF=pci
    export CONFIG_WLAN_FEATURE_11W=y
    export CONFIG_WLAN_FEATURE_FILS=y
    export CONFIG_LINUX_QCMBR=y
    export CONFIG_WLAN_WAPI_MODE_11AC_DISABLE=y
    export CONFIG_WLAN_WOW_PULSE=y
else ifeq ($(IF_TYPE),USB)
    export CONFIG_ROME_IF=usb
    export CONFIG_LINUX_QCMBR=y
    export CONFIG_WLAN_FEATURE_FILS=y
    export CFG80211_CONNECT_BSS=y
    export CONFIG_FEATURE_COEX_PTA_CONFIG_ENABLE=y
    export CONFIG_QOS_FWD_SUPPORT=y
    export CONFIG_QCA_SUPPORT_TXRX_DRIVER_TCP_DEL_ACK=y
    export CONFIG_WLAN_WAPI_MODE_11AC_DISABLE=y
    export CONFIG_WLAN_WOW_PULSE=y
else ifeq ($(IF_TYPE),SDIO)
    export CONFIG_CLD_HL_SDIO_CORE=y
    export CONFIG_LINUX_QCMBR=y
    export CONFIG_PER_VDEV_TX_DESC_POOL=1
    export SAP_AUTH_OFFLOAD=1
    export CONFIG_QCA_LL_TX_FLOW_CT=1
    export CONFIG_WLAN_FEATURE_FILS=y
    export CONFIG_FEATURE_COEX_PTA_CONFIG_ENABLE=y
    export CONFIG_QCA_SUPPORT_TXRX_DRIVER_TCP_DEL_ACK=y
    export CONFIG_WLAN_WAPI_MODE_11AC_DISABLE=y
    export CONFIG_WLAN_WOW_PULSE=y
    export CONFIG_TXRX_PERF=y
endif

all:
	@echo "##############################"
	@echo KERNEL_SRC=$(KERNEL_SRC)
	@echo KERNEL_ARCH=$(ARCH)
	@echo CROSS_COMPILE=$(CROSS_COMPILE)
	@echo "##############################"
	$(MAKE) -C $(TOP)/drivers -j
	mkdir -p $(INSTALL_ROOT)/lib/modules
ifneq ($(OUT_DIR),)
	find ${OUT_DIR}/$(QCACLD) -type f -name 'wlan.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules/ ';'
else
	find $(TOP)/drivers -type f -name 'wlan.ko' -exec cp '{}' $(INSTALL_ROOT)/lib/modules/ ';'
endif
	$(CROSS_COMPILE)strip --strip-unneeded $(INSTALL_ROOT)/lib/modules/*
	@echo "##############################"
	ls -lht $(INSTALL_ROOT)/lib/modules/
	@echo "##############################"

modules_install:
	$(MAKE) -C $(TOP)/drivers/qcacld-new -j modules_install
	mkdir -p ${OUT_DIR}/../vendor_lib/modules
	cp $(INSTALL_ROOT)/lib/modules/wlan.ko ${OUT_DIR}/../vendor_lib/modules/wlan_6174.ko
	rm -vrf $(INSTALL_ROOT)

clean:
	$(MAKE) -C $(TOP)/drivers clean
	rm -rf $(INSTALL_ROOT)

