/*
 * Copyright (c) 2014 The Linux Foundation. All rights reserved.
 *
 * Previously licensed under the ISC license by Qualcomm Atheros, Inc.
 *
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This file was originally distributed by Qualcomm Atheros, Inc.
 * under proprietary terms before Copyright ownership was assigned
 * to the Linux Foundation.
 */

#if !defined( HDD_INCLUDES_H__ )
#define HDD_INCLUDES_H__

/**===========================================================================

  \file  wlan_hdd_includes.h

  \brief Internal includes for the Linux HDD

  ==========================================================================*/

/* $HEADER$ */

/*---------------------------------------------------------------------------
  Include files
  -------------------------------------------------------------------------*/

// throw all the includes in here f to get the .c files  in the HDD to compile.

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/wireless.h>
#include <linux/if_arp.h>


#include <vos_api.h>

#include <sme_Api.h>
#include <wlan_qct_tl.h>

#include "wlan_hdd_assoc.h"
#include "wlan_hdd_dp_utils.h"
#include "wlan_hdd_mib.h"
#include "wlan_hdd_wext.h"
#include "wlan_hdd_main.h"
#include "wlan_hdd_tx_rx.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)) && \
	(defined  IEEE80211_MLD_MAX_NUM_LINKS)
#define CFG80211_SINGLE_NETDEV_MULTI_LINK_SUPPORT 1
#endif

#endif    // end #if !defined( HDD_INCLUDES_H__ )
