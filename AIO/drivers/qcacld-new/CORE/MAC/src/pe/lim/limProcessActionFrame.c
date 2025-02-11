/*
 * Copyright (c) 2012-2014, 2016-2018 The Linux Foundation. All rights reserved.
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


/*
 * This file limProcessActionFrame.cc contains the code
 * for processing Action Frame.
 * Author:      Michael Lui
 * Date:        05/23/03
 * History:-
 * Date           Modified by    Modification Information
 * --------------------------------------------------------------------
 *
 */
#include "palTypes.h"
#include "wniApi.h"
#include "sirApi.h"
#include "aniGlobal.h"
#include "wni_cfg.h"
#include "schApi.h"
#include "utilsApi.h"
#include "limTypes.h"
#include "limUtils.h"
#include "limAssocUtils.h"
#include "limSecurityUtils.h"
#include "limSerDesUtils.h"
#include "limSendSmeRspMessages.h"
#include "parserApi.h"
#include "limAdmitControl.h"
#include "wmmApsd.h"
#include "limSendMessages.h"
#if defined WLAN_FEATURE_VOWIFI
#include "rrmApi.h"
#endif
#include "limSessionUtils.h"

#if defined(FEATURE_WLAN_ESE) && !defined(FEATURE_WLAN_ESE_UPLOAD)
#include "eseApi.h"
#endif
#include "wlan_qct_wda.h"

#include "pmmApi.h"
#include "wma.h"

#define BA_DEFAULT_TX_BUFFER_SIZE 64

typedef enum
{
  LIM_ADDBA_RSP = 0,
  LIM_ADDBA_REQ = 1
}tLimAddBaValidationReqType;

/* Note: The test passes if the STAUT stops sending any frames, and no further
 frames are transmitted on this channel by the station when the AP has sent
 the last 6 beacons, with the channel switch information elements as seen
 with the sniffer.*/
#define SIR_CHANSW_TX_STOP_MAX_COUNT 6
/**-----------------------------------------------------------------
\fn     limStopTxAndSwitchChannel
\brief  Stops the transmission if channel switch mode is silent and
        starts the channel switch timer.

\param  pMac
\return NONE
-----------------------------------------------------------------*/
void limStopTxAndSwitchChannel(tpAniSirGlobal pMac, tANI_U8 sessionId)
{
    tANI_U8 isFullPowerRequested = 0;
    tpPESession psessionEntry;
    tANI_U8 isSessionPowerActive = false;

    psessionEntry = peFindSessionBySessionId( pMac , sessionId );

    if( NULL == psessionEntry )
    {
      limLog(pMac, LOGE, FL("Session %d not active"), sessionId);
      return;
    }

    if(psessionEntry->ftPEContext.pFTPreAuthReq)
    {
        limLog(pMac, LOGE,
           FL("Avoid Switch Channel req during pre auth"));
        return;
    }

    /*
     * Sme Session is passed in limSendSmePreChannelSwitchInd
     * so that it can be passed till sme to request full power for
     * particular session
     */
    if(pMac->psOffloadEnabled)
    {
        isSessionPowerActive = pmmPsOffloadIsActive(pMac, psessionEntry);
    }
    else
    {
        isSessionPowerActive = limIsSystemInActiveState(pMac);
    }

    PELOG1(limLog(pMac, LOG1, FL("Channel switch Mode == %d"),
                       psessionEntry->gLimChannelSwitch.switchMode);)

    if (psessionEntry->gLimChannelSwitch.switchMode == eSIR_CHANSW_MODE_SILENT ||
        psessionEntry->gLimChannelSwitch.switchCount <= SIR_CHANSW_TX_STOP_MAX_COUNT)
    {
        /* Freeze the transmission */
        limFrameTransmissionControl(pMac, eLIM_TX_ALL, eLIM_STOP_TX);

        /*Request for Full power only if the device is in powersave*/
        if(!isSessionPowerActive)
        {
            /* Request Full Power */
            limSendSmePreChannelSwitchInd(pMac, psessionEntry);
            isFullPowerRequested = 1;
        }
    }
    else
    {
        /* Resume the transmission */
        limFrameTransmissionControl(pMac, eLIM_TX_ALL, eLIM_RESUME_TX);
    }

    pMac->lim.limTimers.gLimChannelSwitchTimer.sessionId = sessionId;
    /* change the channel immediatly only if the channel switch count is 0 and the
     * device is not in powersave
     * If the device is in powersave channel switch should happen only after the
     * device comes out of the powersave */
    if (psessionEntry->gLimChannelSwitch.switchCount == 0)
    {
        if(isSessionPowerActive)
        {
            limProcessChannelSwitchTimeout(pMac);
        }
        else if(!isFullPowerRequested)
        {
            /*
             * If the Full power is already not requested
             * Request Full Power so the channel switch happens
             * after device comes to full power
             */
            limSendSmePreChannelSwitchInd(pMac, psessionEntry);
        }
        return;
    }
    MTRACE(macTrace(pMac, TRACE_CODE_TIMER_ACTIVATE, sessionId, eLIM_CHANNEL_SWITCH_TIMER));


    if (tx_timer_activate(&pMac->lim.limTimers.gLimChannelSwitchTimer) != TX_SUCCESS)
    {
        limLog(pMac, LOGP, FL("tx_timer_activate failed"));
    }
    return;
}

/**------------------------------------------------------------
\fn     limStartChannelSwitch
\brief  Switches the channel if switch count == 0, otherwise
        starts the timer for channel switch and stops BG scan
        and heartbeat timer tempororily.

\param  pMac
\param  psessionEntry
\return NONE
------------------------------------------------------------*/
tSirRetStatus limStartChannelSwitch(tpAniSirGlobal pMac, tpPESession psessionEntry)
{
    PELOG1(limLog(pMac, LOG1, FL("Starting the channel switch"));)

    /*If channel switch is already running and it is on a different session, just return*/
    /*This need to be removed for MCC */
    if ((limIsChanSwitchRunning (pMac) &&
        psessionEntry->gLimSpecMgmt.dot11hChanSwState != eLIM_11H_CHANSW_RUNNING) ||
        psessionEntry->csaOffloadEnable)
    {
       limLog(pMac, LOGW, FL("Ignoring channel switch on session %d"), psessionEntry->peSessionId);
       return eSIR_SUCCESS;
    }

    /* Deactivate and change reconfigure the timeout value */
    //limDeactivateAndChangeTimer(pMac, eLIM_CHANNEL_SWITCH_TIMER);
    MTRACE(macTrace(pMac, TRACE_CODE_TIMER_DEACTIVATE, psessionEntry->peSessionId, eLIM_CHANNEL_SWITCH_TIMER));
    if (tx_timer_deactivate(&pMac->lim.limTimers.gLimChannelSwitchTimer) != eSIR_SUCCESS)
    {
        limLog(pMac, LOGP, FL("tx_timer_deactivate failed!"));
        return eSIR_FAILURE;
    }

    if (tx_timer_change(&pMac->lim.limTimers.gLimChannelSwitchTimer,
                psessionEntry->gLimChannelSwitch.switchTimeoutValue,
                            0) != TX_SUCCESS)
    {
        limLog(pMac, LOGP, FL("tx_timer_change failed "));
        return eSIR_FAILURE;
    }

    /* Follow the channel switch, forget about the previous quiet. */
    //If quiet is running, chance is there to resume tx on its timeout.
    //so stop timer for a safer side.
    if (psessionEntry->gLimSpecMgmt.quietState == eLIM_QUIET_BEGIN)
    {
        MTRACE(macTrace(pMac, TRACE_CODE_TIMER_DEACTIVATE, psessionEntry->peSessionId, eLIM_QUIET_TIMER));
        if (tx_timer_deactivate(&pMac->lim.limTimers.gLimQuietTimer) != TX_SUCCESS)
        {
            limLog(pMac, LOGP, FL("tx_timer_deactivate failed"));
            return eSIR_FAILURE;
        }
    }
    else if (psessionEntry->gLimSpecMgmt.quietState == eLIM_QUIET_RUNNING)
    {
        MTRACE(macTrace(pMac, TRACE_CODE_TIMER_DEACTIVATE, psessionEntry->peSessionId, eLIM_QUIET_BSS_TIMER));
        if (tx_timer_deactivate(&pMac->lim.limTimers.gLimQuietBssTimer) != TX_SUCCESS)
        {
            limLog(pMac, LOGP, FL("tx_timer_deactivate failed"));
            return eSIR_FAILURE;
        }
    }
    psessionEntry->gLimSpecMgmt.quietState = eLIM_QUIET_INIT;

    /* Prepare for 11h channel switch */
    limPrepareFor11hChannelSwitch(pMac, psessionEntry);

    /** Dont add any more statements here as we posted finish scan request
     * to HAL, wait till we get the response
     */
    return eSIR_SUCCESS;
}


/**
 *  __limProcessChannelSwitchActionFrame
 *
 *FUNCTION:
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param  pMac - Pointer to Global MAC structure
 * @param  *pRxPacketInfo - A pointer to packet info structure
 * @return None
 */

static void

__limProcessChannelSwitchActionFrame(tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo,tpPESession psessionEntry)
{

    tpSirMacMgmtHdr         pHdr;
    tANI_U8                 *pBody;
    tDot11fChannelSwitch    *pChannelSwitchFrame;
    tANI_U16                beaconPeriod;
    tANI_U32                val;
    tANI_U32                frameLen;
    tANI_U32                nStatus;

    pHdr = WDA_GET_RX_MAC_HEADER(pRxPacketInfo);
    pBody = WDA_GET_RX_MPDU_DATA(pRxPacketInfo);
    frameLen = WDA_GET_RX_PAYLOAD_LEN(pRxPacketInfo);

    PELOG3(limLog(pMac, LOG3, FL("Received Channel switch action frame"));)
    if (!psessionEntry->lim11hEnable)
        return;

    pChannelSwitchFrame = vos_mem_malloc(sizeof(*pChannelSwitchFrame));
    if (NULL == pChannelSwitchFrame)
    {
        limLog(pMac, LOGE,
            FL("AllocateMemory failed"));
        return;
    }

    /* Unpack channel switch frame */
    nStatus = dot11fUnpackChannelSwitch(pMac, pBody, frameLen, pChannelSwitchFrame);

    if( DOT11F_FAILED( nStatus ))
    {
        limLog( pMac, LOGE,
            FL( "Failed to unpack and parse an 11h-CHANSW Request (0x%08x, %d bytes):"),
            nStatus,
            frameLen);
        vos_mem_free(pChannelSwitchFrame);
        return;
    }
    else if(DOT11F_WARNED( nStatus ))
    {
        limLog( pMac, LOGW,
            FL( "There were warnings while unpacking an 11h-CHANSW Request (0x%08x, %d bytes):"),
            nStatus,
            frameLen);
    }

    if (vos_mem_compare((tANI_U8 *) &psessionEntry->bssId,
                        (tANI_U8 *) &pHdr->sa,
                        sizeof(tSirMacAddr)))
    {
        /* copy the beacon interval from psessionEntry*/
        val = psessionEntry->beaconParams.beaconInterval;

        beaconPeriod = (tANI_U16) val;

        psessionEntry->gLimChannelSwitch.primaryChannel = pChannelSwitchFrame->ChanSwitchAnn.newChannel;
        psessionEntry->gLimChannelSwitch.switchCount = pChannelSwitchFrame->ChanSwitchAnn.switchCount;
        psessionEntry->gLimChannelSwitch.switchTimeoutValue = SYS_MS_TO_TICKS(beaconPeriod) *
                                                         psessionEntry->gLimChannelSwitch.switchCount;
        psessionEntry->gLimChannelSwitch.switchMode = pChannelSwitchFrame->ChanSwitchAnn.switchMode;
#ifdef WLAN_FEATURE_11AC
        if ( pChannelSwitchFrame->WiderBWChanSwitchAnn.present && psessionEntry->vhtCapability)
        {
            psessionEntry->gLimWiderBWChannelSwitch.newChanWidth = pChannelSwitchFrame->WiderBWChanSwitchAnn.newChanWidth;
            psessionEntry->gLimWiderBWChannelSwitch.newCenterChanFreq0 = pChannelSwitchFrame->WiderBWChanSwitchAnn.newCenterChanFreq0;
            psessionEntry->gLimWiderBWChannelSwitch.newCenterChanFreq1 = pChannelSwitchFrame->WiderBWChanSwitchAnn.newCenterChanFreq1;
        }
#endif

       PELOG3(limLog(pMac, LOG3, FL("Rcv Chnl Swtch Frame: Timeout in %d ticks"),
                             psessionEntry->gLimChannelSwitch.switchTimeoutValue);)

        /* Only primary channel switch element is present */
        psessionEntry->gLimChannelSwitch.state = eLIM_CHANNEL_SWITCH_PRIMARY_ONLY;
        psessionEntry->gLimChannelSwitch.secondarySubBand = PHY_SINGLE_CHANNEL_CENTERED;

        if (psessionEntry->htSupportedChannelWidthSet) {
            if ((pChannelSwitchFrame->sec_chan_offset_ele.
                 secondaryChannelOffset == PHY_DOUBLE_CHANNEL_LOW_PRIMARY) ||
                (pChannelSwitchFrame->sec_chan_offset_ele.
                 secondaryChannelOffset == PHY_DOUBLE_CHANNEL_HIGH_PRIMARY)) {
                psessionEntry->gLimChannelSwitch.state =
                        eLIM_CHANNEL_SWITCH_PRIMARY_AND_SECONDARY;
                psessionEntry->gLimChannelSwitch.secondarySubBand =
                pChannelSwitchFrame->sec_chan_offset_ele.secondaryChannelOffset;
            }
#ifdef WLAN_FEATURE_11AC
            if(psessionEntry->vhtCapability &&
                pChannelSwitchFrame->WiderBWChanSwitchAnn.present) {
                if (pChannelSwitchFrame->WiderBWChanSwitchAnn.newChanWidth ==
                    WNI_CFG_VHT_CHANNEL_WIDTH_80MHZ) {
                    if (pChannelSwitchFrame->sec_chan_offset_ele.present &&
                        ((pChannelSwitchFrame->sec_chan_offset_ele.
                        secondaryChannelOffset ==
                        PHY_DOUBLE_CHANNEL_LOW_PRIMARY) ||
                        (pChannelSwitchFrame->sec_chan_offset_ele.
                        secondaryChannelOffset ==
                        PHY_DOUBLE_CHANNEL_HIGH_PRIMARY))) {
                        psessionEntry->gLimChannelSwitch.state =
                            eLIM_CHANNEL_SWITCH_PRIMARY_AND_SECONDARY;
                        psessionEntry->gLimChannelSwitch.secondarySubBand =
                           limGet11ACPhyCBState(pMac,
                                psessionEntry->gLimChannelSwitch.primaryChannel,
                                pChannelSwitchFrame->sec_chan_offset_ele.
                                secondaryChannelOffset,
                                pChannelSwitchFrame->WiderBWChanSwitchAnn.
                                newCenterChanFreq0,
                                psessionEntry);
                    }
                }
            }
#endif
        }

    }
    else
    {
        PELOG1(limLog(pMac, LOG1, FL("LIM: Received action frame not from our BSS, dropping..."));)
    }

    if (eSIR_SUCCESS != limStartChannelSwitch(pMac, psessionEntry))
    {
        PELOG1(limLog(pMac, LOG1, FL("Could not start channel switch"));)
    }

    vos_mem_free(pChannelSwitchFrame);
    return;
} /*** end limProcessChannelSwitchActionFrame() ***/

/**
 * lim_process_ext_channel_switch_action_frame()- Process ECSA Action
 * Frames.
 * @mac_ctx: pointer to global mac structure
 * @rx_packet_info: rx packet meta information
 * @session_entry: Session entry.
 *
 * This function is called when ECSA action frame is received.
 *
 * Return: void
 */
static void
lim_process_ext_channel_switch_action_frame(tpAniSirGlobal mac_ctx,
		uint8_t *rx_packet_info, tpPESession session_entry)
{

	tpSirMacMgmtHdr         hdr;
	uint8_t                 *body;
	tDot11fext_channel_switch_action_frame *ext_channel_switch_frame;
	uint32_t                frame_len;
	uint32_t                status;
	uint8_t                 target_channel;

	hdr = WDA_GET_RX_MAC_HEADER(rx_packet_info);
	body = WDA_GET_RX_MPDU_DATA(rx_packet_info);
	frame_len = WDA_GET_RX_PAYLOAD_LEN(rx_packet_info);

	limLog(mac_ctx, LOG1, FL("Received EXT Channel switch action frame"));

	ext_channel_switch_frame =
		 vos_mem_malloc(sizeof(*ext_channel_switch_frame));
	if (NULL == ext_channel_switch_frame) {
		limLog(mac_ctx, LOGE, FL("AllocateMemory failed"));
		return;
	}

	/* Unpack channel switch frame */
	status = dot11fUnpackext_channel_switch_action_frame(mac_ctx,
			body, frame_len, ext_channel_switch_frame);

	if (DOT11F_FAILED(status)) {

		limLog( mac_ctx, LOGE,
			FL( "Failed to parse CHANSW action frame (0x%08x, len %d):"),
			status, frame_len);
		vos_mem_free(ext_channel_switch_frame);
		return;
	} else if (DOT11F_WARNED(status)) {

		limLog( mac_ctx, LOGW,
		  FL( "There were warnings while unpacking CHANSW Request (0x%08x, %d bytes):"),
		  status, frame_len);
	}

	target_channel =
	 ext_channel_switch_frame->ext_chan_switch_ann_action.new_channel;

	/* Free ext_channel_switch_frame here as its no longer needed */
	vos_mem_free(ext_channel_switch_frame);
	/*
	 * Now, validate if channel change is required for the passed
	 * channel and if is valid in the current regulatory domain,
	 * and no concurrent session is running.
	 */
	if (!((session_entry->currentOperChannel != target_channel) &&
	 ((vos_nv_getChannelEnabledState(target_channel)
							== NV_CHANNEL_ENABLE) ||
	 (vos_nv_getChannelEnabledState(target_channel) == NV_CHANNEL_DFS &&
	 !vos_concurrent_open_sessions_running())))) {
		limLog(mac_ctx, LOGE, FL(" Channel %d is not valid"),
							target_channel);
		return;
	}

	if ((eLIM_STA_ROLE == session_entry->limSystemRole) || \
	    (eLIM_P2P_DEVICE_CLIENT == session_entry->limSystemRole)) {

		struct sir_sme_ext_cng_chan_ind *ext_cng_chan_ind;
		tSirMsgQ mmh_msg;

		ext_cng_chan_ind = vos_mem_malloc(sizeof(*ext_cng_chan_ind));
		if (NULL == ext_cng_chan_ind) {
			limLog(mac_ctx, LOGP,
			  FL("AllocateMemory failed for ext_cng_chan_ind"));
			return;
		}

		vos_mem_zero(ext_cng_chan_ind,
			sizeof(*ext_cng_chan_ind));
		ext_cng_chan_ind->session_id=
					session_entry->smeSessionId;

		/* No need to extract op mode as BW will be decided in
		 *  in SAP FSM depending on previous BW.
		 */
		ext_cng_chan_ind->new_channel = target_channel;

		mmh_msg.type = eWNI_SME_EXT_CHANGE_CHANNEL_IND;
		mmh_msg.bodyptr = ext_cng_chan_ind;
		mmh_msg.bodyval = 0;
		limSysProcessMmhMsgApi(mac_ctx, &mmh_msg, ePROT);
	}
	return;
} /*** end lim_process_ext_channel_switch_action_frame() ***/


#ifdef WLAN_FEATURE_11AC
static void
__limProcessOperatingModeActionFrame(tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo,tpPESession psessionEntry)
{

    tpSirMacMgmtHdr         pHdr;
    tANI_U8                 *pBody;
    tDot11fOperatingMode    *pOperatingModeframe;
    tANI_U32                frameLen;
    tANI_U32                nStatus;
    tpDphHashNode           pSta;
    tANI_U16                aid;
    tANI_U8  operMode;
    tANI_U8  cbMode;
    tANI_U8  ch_bw = 0;
    tANI_U8  skip_opmode_update = false;

    pHdr = WDA_GET_RX_MAC_HEADER(pRxPacketInfo);
    pBody = WDA_GET_RX_MPDU_DATA(pRxPacketInfo);
    frameLen = WDA_GET_RX_PAYLOAD_LEN(pRxPacketInfo);

    limLog(pMac, LOG1, FL("Received Operating Mode action frame"));

    if (RF_CHAN_14 >= psessionEntry->currentOperChannel)
        cbMode = pMac->roam.configParam.channelBondingMode24GHz;
    else
        cbMode = pMac->roam.configParam.channelBondingMode5GHz;

    /* Do not update the channel bonding mode if channel bonding
     * mode is disabled in INI.
     */
    if (WNI_CFG_CHANNEL_BONDING_MODE_DISABLE == cbMode) {
        limLog(pMac, LOGW, FL("channel bonding disabled"));
        return;
    }

    pOperatingModeframe = vos_mem_malloc(sizeof(*pOperatingModeframe));
    if (NULL == pOperatingModeframe)
    {
        limLog(pMac, LOGE,
            FL("AllocateMemory failed"));
        return;
    }

    /* Unpack channel switch frame */
    nStatus = dot11fUnpackOperatingMode(pMac, pBody, frameLen, pOperatingModeframe);

    if( DOT11F_FAILED( nStatus ))
    {
        limLog( pMac, LOGE,
            FL( "Failed to unpack and parse an 11h-CHANSW Request (0x%08x, %d bytes):"),
            nStatus,
            frameLen);
        vos_mem_free(pOperatingModeframe);
        return;
    }
    else if(DOT11F_WARNED( nStatus ))
    {
        limLog( pMac, LOGW,
            FL( "There were warnings while unpacking an 11h-CHANSW Request (0x%08x, %d bytes):"),
            nStatus,
            frameLen);
    }
    pSta = dphLookupHashEntry(pMac, pHdr->sa, &aid, &psessionEntry->dph.dphHashTable);

    if (pSta == NULL) {
        limLog(pMac, LOGE, FL("Station context not found"));
        goto end;
    }

    operMode = pSta->vhtSupportedChannelWidthSet ? eHT_CHANNEL_WIDTH_80MHZ : pSta->htSupportedChannelWidthSet ? eHT_CHANNEL_WIDTH_40MHZ: eHT_CHANNEL_WIDTH_20MHZ;

    if ((operMode == eHT_CHANNEL_WIDTH_80MHZ) &&
        (pOperatingModeframe->OperatingMode.chanWidth >
             eHT_CHANNEL_WIDTH_80MHZ))
        skip_opmode_update = true;

    if (!skip_opmode_update &&
        (operMode != pOperatingModeframe->OperatingMode.chanWidth))
    {
        uint32_t fw_vht_ch_wd = wma_get_vht_ch_width();
        limLog(pMac, LOGE,
            FL(" received Chanwidth %d, staIdx = %d"),
            (pOperatingModeframe->OperatingMode.chanWidth ),
            pSta->staIndex);

        limLog(pMac, LOGE,
            FL(" MAC - %0x:%0x:%0x:%0x:%0x:%0x"),
            pHdr->sa[0],
            pHdr->sa[1],
            pHdr->sa[2],
            pHdr->sa[3],
            pHdr->sa[4],
            pHdr->sa[5]);

        if ((pOperatingModeframe->OperatingMode.chanWidth >
                eHT_CHANNEL_WIDTH_80MHZ) &&
             (fw_vht_ch_wd > eHT_CHANNEL_WIDTH_80MHZ)) {
            pSta->vhtSupportedChannelWidthSet =
                WNI_CFG_VHT_CHANNEL_WIDTH_160MHZ;
            pSta->htSupportedChannelWidthSet = eHT_CHANNEL_WIDTH_40MHZ;
            ch_bw = eHT_CHANNEL_WIDTH_160MHZ;
        } else if(pOperatingModeframe->OperatingMode.chanWidth >=
                eHT_CHANNEL_WIDTH_80MHZ) {
            pSta->vhtSupportedChannelWidthSet = WNI_CFG_VHT_CHANNEL_WIDTH_80MHZ;
            pSta->htSupportedChannelWidthSet = eHT_CHANNEL_WIDTH_40MHZ;
            ch_bw = eHT_CHANNEL_WIDTH_80MHZ;
        } else if(pOperatingModeframe->OperatingMode.chanWidth ==
                eHT_CHANNEL_WIDTH_40MHZ) {
            pSta->vhtSupportedChannelWidthSet =
                WNI_CFG_VHT_CHANNEL_WIDTH_20_40MHZ;
            pSta->htSupportedChannelWidthSet = eHT_CHANNEL_WIDTH_40MHZ;
            ch_bw = eHT_CHANNEL_WIDTH_40MHZ;
        } else if(pOperatingModeframe->OperatingMode.chanWidth ==
                eHT_CHANNEL_WIDTH_20MHZ) {
            pSta->vhtSupportedChannelWidthSet =
                WNI_CFG_VHT_CHANNEL_WIDTH_20_40MHZ;
            pSta->htSupportedChannelWidthSet = eHT_CHANNEL_WIDTH_20MHZ;
            ch_bw = eHT_CHANNEL_WIDTH_20MHZ;
        }
        limCheckVHTOpModeChange(pMac, psessionEntry,
                                 ch_bw, MODE_MAX,
                                 pSta->staIndex, pHdr->sa);
    }

    if (pSta->vhtSupportedRxNss != (pOperatingModeframe->OperatingMode.rxNSS + 1)) {
        pSta->vhtSupportedRxNss = pOperatingModeframe->OperatingMode.rxNSS + 1;
        limSetNssChange( pMac, psessionEntry, pSta->vhtSupportedRxNss,
                         pSta->staIndex, pHdr->sa);
    }
end:
    vos_mem_free(pOperatingModeframe);
    return;
}

static void
__limProcessGidManagementActionFrame(tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo,tpPESession psessionEntry)
{

    tpSirMacMgmtHdr         pHdr;
    tANI_U8                 *pBody;
    tDot11fVHTGidManagementActionFrame    *pGidManagementframe;
    tANI_U32                frameLen;
    tANI_U32                nStatus;
    tpDphHashNode           pSta;
    tANI_U16                aid;
    tANI_U32                membership = 0;
    tANI_U32                userPosition = 0;
    tANI_U32                *pMemLower;
    tANI_U32                *pMemUpper;
    tANI_U32                *pMemCur;

    pHdr = WDA_GET_RX_MAC_HEADER(pRxPacketInfo);
    pBody = WDA_GET_RX_MPDU_DATA(pRxPacketInfo);
    frameLen = WDA_GET_RX_PAYLOAD_LEN(pRxPacketInfo);

    PELOG3(limLog(pMac, LOG3, FL("Received GID Management action frame"));)
    pGidManagementframe = vos_mem_malloc(sizeof(*pGidManagementframe));
    if (NULL == pGidManagementframe)
    {
        limLog(pMac, LOGE,
            FL("AllocateMemory failed"));
        return;
    }

    /* Unpack Gid Mangement Action frame */
    nStatus = dot11fUnpackVHTGidManagementActionFrame(pMac, pBody, frameLen, pGidManagementframe);

    if( DOT11F_FAILED( nStatus ))
    {
        limLog( pMac, LOGE,
            FL( "Failed to unpack and parse an GidManagement Action frame (0x%08x, %d bytes):"),
            nStatus,
            frameLen);
        vos_mem_free(pGidManagementframe);
        return;
    }
    else if(DOT11F_WARNED( nStatus ))
    {
        limLog( pMac, LOGW,
            FL( "There were warnings while unpacking an GidManagement Action frame (0x%08x, %d bytes):"),
            nStatus,
            frameLen);
    }
    pSta = dphLookupHashEntry(pMac, pHdr->sa, &aid, &psessionEntry->dph.dphHashTable);

    if (pSta != NULL) {
        limLog(pMac, LOGE,
            FL(" received Gid Management Action Frame , staIdx = %d"),
               pSta->staIndex);

        limLog(pMac, LOGE,
            FL(" MAC - %0x:%0x:%0x:%0x:%0x:%0x"),
            pHdr->sa[0],
            pHdr->sa[1],
            pHdr->sa[2],
            pHdr->sa[3],
            pHdr->sa[4],
            pHdr->sa[5]);

        pMemLower = (tANI_U32 *)pGidManagementframe->VhtMembershipStatusArray.membershipStatusArray;
        pMemUpper = (tANI_U32 *)&pGidManagementframe->VhtMembershipStatusArray.membershipStatusArray[4];

        if (*pMemLower && *pMemUpper)
        {
            limLog(pMac, LOGE,
                   FL(" received frame with multiple group ID set, staIdx = %d"),
                   pSta->staIndex);
            goto out;
        }
        if (*pMemLower)
        {
            pMemCur = pMemLower;
        }
        else if (*pMemUpper)
        {
            pMemCur = pMemUpper;
            membership += sizeof(tANI_U32);
        }
        else
        {
            limLog(pMac, LOGE,
                   FL(" received Gid Management Frame with no group ID set, staIdx = %d"),
                   pSta->staIndex);
            goto out;
        }
        while (!(*pMemCur & 1))
        {
                *pMemCur >>= 1;
                ++membership;
        }
        if (*pMemCur)
        {
                limLog(pMac, LOGE,
                       FL(" received frame with multiple group ID set, staIdx = %d"),
                       pSta->staIndex);
                goto out;
        }

        /*Just read the last two bits */
        userPosition = pGidManagementframe->VhtUserPositionArray.userPositionArray[membership]
                                            & 0x3;

        limCheckMembershipUserPosition( pMac, psessionEntry, membership,
                                 userPosition, pSta->staIndex);
    }
out:
    vos_mem_free(pGidManagementframe);
    return;
}

#endif

static void
__limProcessAddTsReq(tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo,tpPESession psessionEntry)
{
}


static void
__limProcessAddTsRsp(tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo,tpPESession psessionEntry)
{
    tSirAddtsRspInfo addts;
    tSirRetStatus    retval;
    tpSirMacMgmtHdr  pHdr;
    tpDphHashNode    pSta;
    tANI_U16         aid;
    tANI_U32         frameLen;
    tANI_U8          *pBody;
    tpLimTspecInfo   tspecInfo;
    tANI_U8          ac;
    tpDphHashNode    pStaDs = NULL;
    tANI_U8          rspReqd = 1;
    tANI_U32   cfgLen;
    tSirMacAddr  peerMacAddr;


    pHdr = WDA_GET_RX_MAC_HEADER(pRxPacketInfo);
    pBody = WDA_GET_RX_MPDU_DATA(pRxPacketInfo);
    frameLen = WDA_GET_RX_PAYLOAD_LEN(pRxPacketInfo);


    PELOGW(limLog(pMac, LOGW, "Recv AddTs Response");)
    if (LIM_IS_AP_ROLE(psessionEntry) || LIM_IS_BT_AMP_AP_ROLE(psessionEntry)) {
        PELOGW(limLog(pMac, LOGW, FL("AddTsRsp recvd at AP: ignoring"));)
        return;
    }

    pSta = dphLookupHashEntry(pMac, pHdr->sa, &aid, &psessionEntry->dph.dphHashTable);
    if (pSta == NULL)
    {
        PELOGE(limLog(pMac, LOGE, FL("Station context not found - ignoring AddTsRsp"));)
        return;
    }

    retval = sirConvertAddtsRsp2Struct(pMac, pBody, frameLen, &addts);
    if (retval != eSIR_SUCCESS)
    {
        PELOGW(limLog(pMac, LOGW, FL("AddTsRsp parsing failed (error %d)"), retval);)
        return;
    }

    // don't have to check for qos/wme capabilities since we wouldn't have this
    // flag set otherwise
    if (! pMac->lim.gLimAddtsSent)
    {
        // we never sent an addts request!
        PELOGW(limLog(pMac, LOGW, "Recvd AddTsRsp but no request was ever sent - ignoring");)
        return;
    }

    if (pMac->lim.gLimAddtsReq.req.dialogToken != addts.dialogToken)
    {
        limLog(pMac, LOGW, "AddTsRsp: token mismatch (got %d, exp %d) - ignoring",
               addts.dialogToken, pMac->lim.gLimAddtsReq.req.dialogToken);
        return;
    }

    /*
     * for successful addts reponse, try to add the classifier.
     * if this fails for any reason, we should send a delts request to the ap
     * for now, its ok not to send a delts since we are going to add support for
     * multiple tclas soon and until then we won't send any addts requests with
     * multiple tclas elements anyway.
     * In case of addClassifier failure, we just let the addts timer run out
     */
    if (((addts.tspec.tsinfo.traffic.accessPolicy == SIR_MAC_ACCESSPOLICY_HCCA) ||
         (addts.tspec.tsinfo.traffic.accessPolicy == SIR_MAC_ACCESSPOLICY_BOTH)) &&
        (addts.status == eSIR_MAC_SUCCESS_STATUS))
    {
        // add the classifier - this should always succeed
        if (addts.numTclas > 1) // currently no support for multiple tclas elements
        {
            limLog(pMac, LOGE, FL("Sta %d: Too many Tclas (%d), only 1 supported"),
                   aid, addts.numTclas);
            return;
        }
        else if (addts.numTclas == 1)
        {
            limLog(pMac, LOGW, "AddTs Response from STA %d: tsid %d, UP %d, OK!", aid,
                   addts.tspec.tsinfo.traffic.tsid, addts.tspec.tsinfo.traffic.userPrio);
        }
    }
    limLog(pMac, LOGW, "Recv AddTsRsp: tsid %d, UP %d, status %d ",
          addts.tspec.tsinfo.traffic.tsid, addts.tspec.tsinfo.traffic.userPrio,
          addts.status);

    // deactivate the response timer
    limDeactivateAndChangeTimer(pMac, eLIM_ADDTS_RSP_TIMER);

    if (addts.status != eSIR_MAC_SUCCESS_STATUS)
    {
        limLog(pMac, LOGW, "Recv AddTsRsp: tsid %d, UP %d, status %d ",
              addts.tspec.tsinfo.traffic.tsid, addts.tspec.tsinfo.traffic.userPrio,
              addts.status);
        limSendSmeAddtsRsp(pMac, true, addts.status, psessionEntry, addts.tspec,
                psessionEntry->smeSessionId, psessionEntry->transactionId);

        // clear the addts flag
        pMac->lim.gLimAddtsSent = false;

        return;
    }
#ifdef FEATURE_WLAN_ESE
    if (addts.tsmPresent) {
        limLog(pMac, LOGW, "TSM IE Present");
        psessionEntry->eseContext.tsm.tid = addts.tspec.tsinfo.traffic.userPrio;
        vos_mem_copy(&psessionEntry->eseContext.tsm.tsmInfo,
                                         &addts.tsmIE,sizeof(tSirMacESETSMIE));
#ifdef FEATURE_WLAN_ESE_UPLOAD
        limSendSmeTsmIEInd(pMac, psessionEntry, addts.tsmIE.tsid,
                           addts.tsmIE.state, addts.tsmIE.msmt_interval);
#else
        limActivateTSMStatsTimer(pMac, psessionEntry);
#endif /* FEATURE_WLAN_ESE_UPLOAD */
    }
#endif
    /* Since AddTS response was successful, check for the PSB flag
     * and directional flag inside the TS Info field.
     * An AC is trigger enabled AC if the PSB subfield is set to 1
     * in the uplink direction.
     * An AC is delivery enabled AC if the PSB subfield is set to 1
     * in the downlink direction.
     * An AC is trigger and delivery enabled AC if the PSB subfield
     * is set to 1 in the bi-direction field.
     */
    if(!pMac->psOffloadEnabled)
    {
        if (addts.tspec.tsinfo.traffic.psb == 1)
            limSetTspecUapsdMask(pMac, &addts.tspec.tsinfo, SET_UAPSD_MASK);
        else
            limSetTspecUapsdMask(pMac, &addts.tspec.tsinfo, CLEAR_UAPSD_MASK);


        /*
         * ADDTS success, so AC is now admitted. We shall now use the default
         * EDCA parameters as advertised by AP and send the updated EDCA params
         * to HAL.
         */
        ac = upToAc(addts.tspec.tsinfo.traffic.userPrio);
        if(addts.tspec.tsinfo.traffic.direction == SIR_MAC_DIRECTION_UPLINK)
        {
            pMac->lim.gAcAdmitMask[SIR_MAC_DIRECTION_UPLINK] |= (1 << ac);
        }
        else if(addts.tspec.tsinfo.traffic.direction == SIR_MAC_DIRECTION_DNLINK)
        {
            pMac->lim.gAcAdmitMask[SIR_MAC_DIRECTION_DNLINK] |= (1 << ac);
        }
        else if(addts.tspec.tsinfo.traffic.direction == SIR_MAC_DIRECTION_BIDIR)
        {
            pMac->lim.gAcAdmitMask[SIR_MAC_DIRECTION_UPLINK] |= (1 << ac);
            pMac->lim.gAcAdmitMask[SIR_MAC_DIRECTION_DNLINK] |= (1 << ac);
        }
    }
    else
    {
        if (addts.tspec.tsinfo.traffic.psb == 1)
            limSetTspecUapsdMaskPerSession(pMac, psessionEntry,
                          &addts.tspec.tsinfo, SET_UAPSD_MASK);
        else
            limSetTspecUapsdMaskPerSession(pMac, psessionEntry,
                        &addts.tspec.tsinfo, CLEAR_UAPSD_MASK);

        /*
         * ADDTS success, so AC is now admitted. We shall now use the default
         * EDCA parameters as advertised by AP and send the updated EDCA params
         * to HAL.
         */
        ac = upToAc(addts.tspec.tsinfo.traffic.userPrio);
        if(addts.tspec.tsinfo.traffic.direction == SIR_MAC_DIRECTION_UPLINK)
        {
            psessionEntry->gAcAdmitMask[SIR_MAC_DIRECTION_UPLINK] |= (1 << ac);
        }
        else if(addts.tspec.tsinfo.traffic.direction == SIR_MAC_DIRECTION_DNLINK)
        {
            psessionEntry->gAcAdmitMask[SIR_MAC_DIRECTION_DNLINK] |= (1 << ac);
        }
        else if(addts.tspec.tsinfo.traffic.direction == SIR_MAC_DIRECTION_BIDIR)
        {
            psessionEntry->gAcAdmitMask[SIR_MAC_DIRECTION_UPLINK] |= (1 << ac);
            psessionEntry->gAcAdmitMask[SIR_MAC_DIRECTION_DNLINK] |= (1 << ac);
        }
    }

    limSetActiveEdcaParams(pMac, psessionEntry->gLimEdcaParams, psessionEntry);

    pStaDs = dphGetHashEntry(pMac, DPH_STA_HASH_INDEX_PEER, &psessionEntry->dph.dphHashTable);
    if (pStaDs != NULL)
        limSendEdcaParams(pMac, psessionEntry->gLimEdcaParamsActive,
                          pStaDs->bssId);
    else
        limLog(pMac, LOGE, FL("Self entry missing in Hash Table "));


    sirCopyMacAddr(peerMacAddr,psessionEntry->bssId);

    //if schedule is not present then add TSPEC with svcInterval as 0.
    if(!addts.schedulePresent)
      addts.schedule.svcInterval = 0;
    if(eSIR_SUCCESS != limTspecAdd(pMac, pSta->staAddr, pSta->assocId, &addts.tspec,  addts.schedule.svcInterval, &tspecInfo))
    {
        PELOGE(limLog(pMac, LOGE, FL("Adding entry in lim Tspec Table failed "));)
        limSendDeltsReqActionFrame(pMac, peerMacAddr, rspReqd, &addts.tspec.tsinfo, &addts.tspec,
                psessionEntry);
        pMac->lim.gLimAddtsSent = false;
        return;   //Error handling. send the response with error status. need to send DelTS to tear down the TSPEC status.
    }
    if((addts.tspec.tsinfo.traffic.accessPolicy != SIR_MAC_ACCESSPOLICY_EDCA) ||
       ((upToAc(addts.tspec.tsinfo.traffic.userPrio) < MAX_NUM_AC)))
    {
#ifdef FEATURE_WLAN_ESE
        retval = limSendHalMsgAddTs(pMac,
                                    pSta->staIndex,
                                    tspecInfo->idx,
                                    addts.tspec,
                                    psessionEntry->peSessionId,
                                    addts.tsmIE.msmt_interval);
#else
        retval = limSendHalMsgAddTs(pMac,
                                    pSta->staIndex,
                                    tspecInfo->idx,
                                    addts.tspec,
                                    psessionEntry->peSessionId);
#endif
        if(eSIR_SUCCESS != retval)
        {
            limAdmitControlDeleteTS(pMac, pSta->assocId, &addts.tspec.tsinfo, NULL, &tspecInfo->idx);

            // Send DELTS action frame to AP
            cfgLen = sizeof(tSirMacAddr);
            limSendDeltsReqActionFrame(pMac, peerMacAddr, rspReqd, &addts.tspec.tsinfo, &addts.tspec,
                    psessionEntry);
            limSendSmeAddtsRsp(pMac, true, retval, psessionEntry, addts.tspec,
                    psessionEntry->smeSessionId, psessionEntry->transactionId);
            pMac->lim.gLimAddtsSent = false;
            return;
        }
        PELOGW(limLog(pMac, LOGW, FL("AddTsRsp received successfully(UP %d, TSID %d)"),
           addts.tspec.tsinfo.traffic.userPrio, addts.tspec.tsinfo.traffic.tsid);)
    }
    else
    {
        PELOGW(limLog(pMac, LOGW, FL("AddTsRsp received successfully(UP %d, TSID %d)"),
               addts.tspec.tsinfo.traffic.userPrio, addts.tspec.tsinfo.traffic.tsid);)
        PELOGW(limLog(pMac, LOGW, FL("no ACM: Bypass sending WDA_ADD_TS_REQ to HAL "));)
        // Use the smesessionId and smetransactionId from the PE session context
        limSendSmeAddtsRsp(pMac, true, eSIR_SME_SUCCESS, psessionEntry, addts.tspec,
                psessionEntry->smeSessionId, psessionEntry->transactionId);
    }

    // clear the addts flag
    pMac->lim.gLimAddtsSent = false;
    return;
}


static void
__limProcessDelTsReq(tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo,tpPESession psessionEntry)
{
    tSirRetStatus    retval;
    tSirDeltsReqInfo delts;
    tpSirMacMgmtHdr  pHdr;
    tpDphHashNode    pSta;
    tANI_U32              frameLen;
    tANI_U16              aid;
    tANI_U8              *pBody;
    tANI_U8               tsStatus;
    tSirMacTSInfo   *tsinfo;
    tANI_U8 tspecIdx;
    tANI_U8  ac;
    tpDphHashNode  pStaDs = NULL;


    pHdr = WDA_GET_RX_MAC_HEADER(pRxPacketInfo);
    pBody = WDA_GET_RX_MPDU_DATA(pRxPacketInfo);
    frameLen = WDA_GET_RX_PAYLOAD_LEN(pRxPacketInfo);

    pSta = dphLookupHashEntry(pMac, pHdr->sa, &aid, &psessionEntry->dph.dphHashTable);
    if (pSta == NULL)
    {
        PELOGE(limLog(pMac, LOGE, FL("Station context not found - ignoring DelTs"));)
        return;
    }

    // parse the delts request
    retval = sirConvertDeltsReq2Struct(pMac, pBody, frameLen, &delts);
    if (retval != eSIR_SUCCESS)
    {
        PELOGW(limLog(pMac, LOGW, FL("DelTs parsing failed (error %d)"), retval);)
        return;
    }

    if (delts.wmeTspecPresent)
    {
        if ((!psessionEntry->limWmeEnabled) || (! pSta->wmeEnabled))
        {
            PELOGW(limLog(pMac, LOGW, FL("Ignoring delts request: wme not enabled/capable"));)
            return;
        }
        PELOG2(limLog(pMac, LOG2, FL("WME Delts received"));)
    }
    else if ((psessionEntry->limQosEnabled) && pSta->lleEnabled)
        {
        PELOG2(limLog(pMac, LOG2, FL("11e QoS Delts received"));)
        }
    else if ((psessionEntry->limWsmEnabled) && pSta->wsmEnabled)
        {
        PELOG2(limLog(pMac, LOG2, FL("WSM Delts received"));)
        }
    else
    {
        PELOGW(limLog(pMac, LOGW, FL("Ignoring delts request: qos not enabled/capable"));)
        return;
    }

    tsinfo = delts.wmeTspecPresent ? &delts.tspec.tsinfo : &delts.tsinfo;

    // if no Admit Control, ignore the request
    if ((tsinfo->traffic.accessPolicy == SIR_MAC_ACCESSPOLICY_EDCA))
    {

        if (upToAc(tsinfo->traffic.userPrio) >= MAX_NUM_AC)
        {
            limLog(pMac, LOGW, FL("DelTs with UP %d has no AC - ignoring request"),
                   tsinfo->traffic.userPrio);
            return;
        }
    }

    if (!LIM_IS_AP_ROLE(psessionEntry) &&
        !LIM_IS_BT_AMP_AP_ROLE(psessionEntry))
        limSendSmeDeltsInd(pMac, &delts, aid,psessionEntry);

    // try to delete the TS
    if (eSIR_SUCCESS != limAdmitControlDeleteTS(pMac, pSta->assocId, tsinfo, &tsStatus, &tspecIdx))
    {
        PELOGW(limLog(pMac, LOGW, FL("Unable to Delete TS"));)
        return;
    }

    else if ((tsinfo->traffic.accessPolicy == SIR_MAC_ACCESSPOLICY_HCCA) ||
             (tsinfo->traffic.accessPolicy == SIR_MAC_ACCESSPOLICY_BOTH))
    {
      //Edca only for now.
    }
    else
    {
      //send message to HAL to delete TS
      if(eSIR_SUCCESS != limSendHalMsgDelTs(pMac,
                                            pSta->staIndex,
                                            tspecIdx,
                                            delts,
                                            psessionEntry->peSessionId,
                                            psessionEntry->bssId))
      {
        limLog(pMac, LOGW, FL("DelTs with UP %d failed in limSendHalMsgDelTs - ignoring request"),
                         tsinfo->traffic.userPrio);
         return;
      }
    }

    /* We successfully deleted the TSPEC. Update the dynamic UAPSD Mask.
     * The AC for this TSPEC is no longer trigger enabled if this Tspec
     * was set-up in uplink direction only.
     * The AC for this TSPEC is no longer delivery enabled if this Tspec
     * was set-up in downlink direction only.
     * The AC for this TSPEC is no longer triiger enabled and delivery
     * enabled if this Tspec was a bidirectional TSPEC.
     */
    if(!pMac->psOffloadEnabled)
    {
        limSetTspecUapsdMask(pMac, tsinfo, CLEAR_UAPSD_MASK);


        /* We're deleting the TSPEC.
         * The AC for this TSPEC is no longer admitted in uplink/downlink direction
         * if this TSPEC was set-up in uplink/downlink direction only.
         * The AC for this TSPEC is no longer admitted in both uplink and downlink
         * directions if this TSPEC was a bi-directional TSPEC.
         * If ACM is set for this AC and this AC is admitted only in downlink
         * direction, PE needs to downgrade the EDCA parameter
         * (for the AC for which TS is being deleted) to the
         * next best AC for which ACM is not enabled, and send the
         * updated values to HAL.
         */
        ac = upToAc(tsinfo->traffic.userPrio);

        if(tsinfo->traffic.direction == SIR_MAC_DIRECTION_UPLINK)
        {
            pMac->lim.gAcAdmitMask[SIR_MAC_DIRECTION_UPLINK] &= ~(1 << ac);
        }
        else if(tsinfo->traffic.direction == SIR_MAC_DIRECTION_DNLINK)
        {
            pMac->lim.gAcAdmitMask[SIR_MAC_DIRECTION_DNLINK] &= ~(1 << ac);
        }
        else if(tsinfo->traffic.direction == SIR_MAC_DIRECTION_BIDIR)
        {
            pMac->lim.gAcAdmitMask[SIR_MAC_DIRECTION_UPLINK] &= ~(1 << ac);
            pMac->lim.gAcAdmitMask[SIR_MAC_DIRECTION_DNLINK] &= ~(1 << ac);
        }
    }
    else
    {
        limSetTspecUapsdMaskPerSession(pMac, psessionEntry,
                                       tsinfo, CLEAR_UAPSD_MASK);


        /* We're deleting the TSPEC.
         * The AC for this TSPEC is no longer admitted in uplink/downlink direction
         * if this TSPEC was set-up in uplink/downlink direction only.
         * The AC for this TSPEC is no longer admitted in both uplink and downlink
         * directions if this TSPEC was a bi-directional TSPEC.
         * If ACM is set for this AC and this AC is admitted only in downlink
         * direction, PE needs to downgrade the EDCA parameter
         * (for the AC for which TS is being deleted) to the
         * next best AC for which ACM is not enabled, and send the
         * updated values to HAL.
         */
        ac = upToAc(tsinfo->traffic.userPrio);

        if(tsinfo->traffic.direction == SIR_MAC_DIRECTION_UPLINK)
        {
            psessionEntry->gAcAdmitMask[SIR_MAC_DIRECTION_UPLINK] &= ~(1 << ac);
        }
        else if(tsinfo->traffic.direction == SIR_MAC_DIRECTION_DNLINK)
        {
            psessionEntry->gAcAdmitMask[SIR_MAC_DIRECTION_DNLINK] &= ~(1 << ac);
        }
        else if(tsinfo->traffic.direction == SIR_MAC_DIRECTION_BIDIR)
        {
            psessionEntry->gAcAdmitMask[SIR_MAC_DIRECTION_UPLINK] &= ~(1 << ac);
            psessionEntry->gAcAdmitMask[SIR_MAC_DIRECTION_DNLINK] &= ~(1 << ac);
        }
    }

    limSetActiveEdcaParams(pMac, psessionEntry->gLimEdcaParams, psessionEntry);

    pStaDs = dphGetHashEntry(pMac, DPH_STA_HASH_INDEX_PEER, &psessionEntry->dph.dphHashTable);
    if (pStaDs != NULL)
        limSendEdcaParams(pMac, psessionEntry->gLimEdcaParamsActive,
                          pStaDs->bssId);
    else
        limLog(pMac, LOGE, FL("Self entry missing in Hash Table "));

    PELOG1(limLog(pMac, LOG1, FL("DeleteTS succeeded"));)

#ifdef FEATURE_WLAN_ESE
#ifdef FEATURE_WLAN_ESE_UPLOAD
    limSendSmeTsmIEInd(pMac, psessionEntry, 0, 0, 0);
#else
    limDeactivateAndChangeTimer(pMac,eLIM_TSM_TIMER);
#endif /* FEATURE_WLAN_ESE_UPLOAD */
#endif

}

static void
__limProcessQosMapConfigureFrame(tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo,
                                                     tpPESession psessionEntry)
{
     tpSirMacMgmtHdr  pHdr;
     tANI_U32         frameLen;
     tANI_U8          *pBody;
     tSirRetStatus    retval;
     pHdr = WDA_GET_RX_MAC_HEADER(pRxPacketInfo);
     pBody = WDA_GET_RX_MPDU_DATA(pRxPacketInfo);
     frameLen = WDA_GET_RX_PAYLOAD_LEN(pRxPacketInfo);
     retval = sirConvertQosMapConfigureFrame2Struct(pMac, pBody, frameLen,
                                                        &psessionEntry->QosMapSet);
     if (retval != eSIR_SUCCESS)
     {
         PELOGW(limLog(pMac, LOGE,
         FL("QosMapConfigure frame parsing failed (error %d)"), retval);)
         return;
     }
     limSendSmeMgmtFrameInd(pMac, pHdr->fc.subType, (tANI_U8*)pHdr,
                               frameLen + sizeof(tSirMacMgmtHdr), 0,
                               WDA_GET_RX_CH( pRxPacketInfo ),
                               psessionEntry, 0, RXMGMT_FLAG_NONE);
}

static void
__limProcessSMPowerSaveUpdate(tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo ,tpPESession psessionEntry)
{

        tpSirMacMgmtHdr                           pHdr;
        tDot11fSMPowerSave                    frmSMPower;
        tSirMacHTMIMOPowerSaveState  state;
        tpDphHashNode                             pSta;
        tANI_U16                                        aid;
        tANI_U32                                        frameLen, nStatus;
        tANI_U8                                          *pBody;

        pHdr = WDA_GET_RX_MAC_HEADER( pRxPacketInfo );
        pBody = WDA_GET_RX_MPDU_DATA( pRxPacketInfo );
        frameLen = WDA_GET_RX_PAYLOAD_LEN( pRxPacketInfo );

        pSta = dphLookupHashEntry(pMac, pHdr->sa, &aid, &psessionEntry->dph.dphHashTable );
        if( pSta == NULL ) {
            limLog( pMac, LOGE,FL( "STA context not found - ignoring UpdateSM PSave Mode from " ));
            limPrintMacAddr( pMac, pHdr->sa, LOGW );
            return;
        }

        /**Unpack the received frame */
        nStatus = dot11fUnpackSMPowerSave( pMac, pBody, frameLen, &frmSMPower);

        if( DOT11F_FAILED( nStatus )) {
            limLog( pMac, LOGE, FL( "Failed to unpack and parse a Update SM Power (0x%08x, %d bytes):"),
                                                    nStatus, frameLen );
            PELOG2(sirDumpBuf( pMac, SIR_DBG_MODULE_ID, LOG2, pBody, frameLen );)
            return;
        }else if ( DOT11F_WARNED( nStatus ) ) {
            limLog(pMac, LOGW, FL( "There were warnings while unpacking a SMPower Save update (0x%08x, %d bytes):"),
                                nStatus, frameLen );
            PELOG2(sirDumpBuf( pMac, SIR_DBG_MODULE_ID, LOG2, pBody, frameLen );)
        }

        limLog(pMac, LOGW, FL("Received SM Power save Mode update Frame with PS_Enable:%d"
                            "PS Mode: %d"), frmSMPower.SMPowerModeSet.PowerSave_En,
                                                    frmSMPower.SMPowerModeSet.Mode);

        /** Update in the DPH Table about the Update in the SM Power Save mode*/
        if (frmSMPower.SMPowerModeSet.PowerSave_En && frmSMPower.SMPowerModeSet.Mode)
            state = eSIR_HT_MIMO_PS_DYNAMIC;
        else if ((frmSMPower.SMPowerModeSet.PowerSave_En) && (frmSMPower.SMPowerModeSet.Mode ==0))
            state = eSIR_HT_MIMO_PS_STATIC;
        else if ((frmSMPower.SMPowerModeSet.PowerSave_En == 0) && (frmSMPower.SMPowerModeSet.Mode == 0))
            state = eSIR_HT_MIMO_PS_NO_LIMIT;
        else {
            PELOGW(limLog(pMac, LOGW, FL("Received SM Power save Mode update Frame with invalid mode"));)
            return;
        }

        if (state == pSta->htMIMOPSState) {
            PELOGE(limLog(pMac, LOGE, FL("The PEER is already set in the same mode"));)
            return;
        }

        /** Update in the HAL Station Table for the Update of the Protection Mode */
        pSta->htMIMOPSState = state;
        limPostSMStateUpdate(pMac,pSta->staIndex, pSta->htMIMOPSState,
                             pSta->staAddr, psessionEntry->smeSessionId);
}

#if defined WLAN_FEATURE_VOWIFI

static void
__limProcessRadioMeasureRequest( tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo ,tpPESession psessionEntry )
{
     tpSirMacMgmtHdr                pHdr;
     tDot11fRadioMeasurementRequest frm;
     tANI_U32                       frameLen, nStatus;
     tANI_U8                        *pBody;

     pHdr = WDA_GET_RX_MAC_HEADER( pRxPacketInfo );
     pBody = WDA_GET_RX_MPDU_DATA( pRxPacketInfo );
     frameLen = WDA_GET_RX_PAYLOAD_LEN( pRxPacketInfo );

     if( psessionEntry == NULL )
     {
          return;
     }

     limSendSmeMgmtFrameInd(pMac, pHdr->fc.subType, (tANI_U8*)pHdr,
          frameLen + sizeof(tSirMacMgmtHdr), 0, WDA_GET_RX_CH(pRxPacketInfo),
          psessionEntry, WDA_GET_RX_RSSI_NORMALIZED(pRxPacketInfo),
          RXMGMT_FLAG_NONE);

     /**Unpack the received frame */
     nStatus = dot11fUnpackRadioMeasurementRequest( pMac, pBody, frameLen, &frm );

     if( DOT11F_FAILED( nStatus )) {
          limLog( pMac, LOGE, FL( "Failed to unpack and parse a Radio Measure request (0x%08x, %d bytes):"),
                    nStatus, frameLen );
          PELOG2(sirDumpBuf( pMac, SIR_DBG_MODULE_ID, LOG2, pBody, frameLen );)
               return;
     }else if ( DOT11F_WARNED( nStatus ) ) {
          limLog(pMac, LOGW, FL( "There were warnings while unpacking a Radio Measure request (0x%08x, %d bytes):"),
                    nStatus, frameLen );
          PELOG2(sirDumpBuf( pMac, SIR_DBG_MODULE_ID, LOG2, pBody, frameLen );)
     }

     // Call rrm function to handle the request.

     rrmProcessRadioMeasurementRequest( pMac, pHdr->sa, &frm, psessionEntry );
}

static void
__limProcessLinkMeasurementReq( tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo ,tpPESession psessionEntry )
{
     tpSirMacMgmtHdr               pHdr;
     tDot11fLinkMeasurementRequest frm;
     tANI_U32                      frameLen, nStatus;
     tANI_U8                       *pBody;

     pHdr = WDA_GET_RX_MAC_HEADER( pRxPacketInfo );
     pBody = WDA_GET_RX_MPDU_DATA( pRxPacketInfo );
     frameLen = WDA_GET_RX_PAYLOAD_LEN( pRxPacketInfo );

     if( psessionEntry == NULL )
     {
          return;
     }

     /**Unpack the received frame */
     nStatus = dot11fUnpackLinkMeasurementRequest( pMac, pBody, frameLen, &frm );

     if( DOT11F_FAILED( nStatus )) {
          limLog( pMac, LOGE, FL( "Failed to unpack and parse a Link Measure request (0x%08x, %d bytes):"),
                    nStatus, frameLen );
          PELOG2(sirDumpBuf( pMac, SIR_DBG_MODULE_ID, LOG2, pBody, frameLen );)
               return;
     }else if ( DOT11F_WARNED( nStatus ) ) {
          limLog(pMac, LOGW, FL( "There were warnings while unpacking a Link Measure request (0x%08x, %d bytes):"),
                    nStatus, frameLen );
          PELOG2(sirDumpBuf( pMac, SIR_DBG_MODULE_ID, LOG2, pBody, frameLen );)
     }

     // Call rrm function to handle the request.

     rrmProcessLinkMeasurementRequest( pMac, pRxPacketInfo, &frm, psessionEntry );

}

static void
__limProcessNeighborReport( tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo ,tpPESession psessionEntry )
{
     tpSirMacMgmtHdr               pHdr;
     tDot11fNeighborReportResponse *pFrm;
     tANI_U32                      frameLen, nStatus;
     tANI_U8                       *pBody;

     pHdr = WDA_GET_RX_MAC_HEADER( pRxPacketInfo );
     pBody = WDA_GET_RX_MPDU_DATA( pRxPacketInfo );
     frameLen = WDA_GET_RX_PAYLOAD_LEN( pRxPacketInfo );

     pFrm = vos_mem_malloc(sizeof(tDot11fNeighborReportResponse));
     if (NULL == pFrm)
     {
         limLog(pMac, LOGE, FL("Unable to allocate memory in __limProcessNeighborReport") );
         return;
     }

     if(psessionEntry == NULL)
     {
          vos_mem_free(pFrm);
          return;
     }

     /**Unpack the received frame */
     nStatus = dot11fUnpackNeighborReportResponse( pMac, pBody, frameLen,pFrm );

     if( DOT11F_FAILED( nStatus )) {
          limLog( pMac, LOGE, FL( "Failed to unpack and parse a Neighbor report response (0x%08x, %d bytes):"),
                    nStatus, frameLen );
          PELOG2(sirDumpBuf( pMac, SIR_DBG_MODULE_ID, LOG2, pBody, frameLen );)
          vos_mem_free(pFrm);
          return;
     }else if ( DOT11F_WARNED( nStatus ) ) {
          limLog(pMac, LOGW, FL( "There were warnings while unpacking a Neighbor report response (0x%08x, %d bytes):"),
                    nStatus, frameLen );
          PELOG2(sirDumpBuf( pMac, SIR_DBG_MODULE_ID, LOG2, pBody, frameLen );)
     }

     //Call rrm function to handle the request.
     rrmProcessNeighborReportResponse( pMac, pFrm, psessionEntry );

     vos_mem_free(pFrm);
}

#endif

#ifdef WLAN_FEATURE_11W
/**
 * limProcessSAQueryRequestActionFrame
 *
 *FUNCTION:
 * This function is called by limProcessActionFrame() upon
 * SA query request Action frame reception.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param  pMac - Pointer to Global MAC structure
 * @param  *pRxPacketInfo - Handle to the Rx packet info
 * @param  psessionEntry - PE session entry
 *
 * @return None
 */
static void __limProcessSAQueryRequestActionFrame(tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo, tpPESession psessionEntry)
{
    tpSirMacMgmtHdr     pHdr;
    tANI_U8             *pBody;
    tANI_U8             transId[2];

    /* Prima  --- Below Macro not available in prima
       pHdr = SIR_MAC_BD_TO_MPDUHEADER(pBd);
       pBody = SIR_MAC_BD_TO_MPDUDATA(pBd); */

    pHdr = WDA_GET_RX_MAC_HEADER(pRxPacketInfo);
    pBody = WDA_GET_RX_MPDU_DATA(pRxPacketInfo);

    /* If this is an unprotected SA Query Request, then ignore it. */
    if (pHdr->fc.wep == 0)
        return;

    /*Extract 11w trsansId from SA query request action frame
      In SA query response action frame we will send same transId
      In SA query request action frame:
      Category       : 1 byte
      Action         : 1 byte
      Transaction ID : 2 bytes */
    vos_mem_copy(&transId[0], &pBody[2], 2);

    //Send 11w SA query response action frame
    if (limSendSaQueryResponseFrame(pMac,
                              transId,
                              pHdr->sa,psessionEntry) != eSIR_SUCCESS)
    {
        PELOGE(limLog(pMac, LOGE, FL("fail to send SA query response action frame."));)
        return;
    }
}

/**
 * __limProcessSAQueryResponseActionFrame
 *
 *FUNCTION:
 * This function is called by limProcessActionFrame() upon
 * SA query response Action frame reception.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param  pMac - Pointer to Global MAC structure
 * @param  *pRxPacketInfo - Handle to the Rx packet info
 * @param  psessionEntry - PE session entry
 * @return None
 */
static void __limProcessSAQueryResponseActionFrame(tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo, tpPESession psessionEntry)
{
    tpSirMacMgmtHdr     pHdr;
    tANI_U32            frameLen;
    tANI_U8             *pBody;
    tpDphHashNode       pSta;
    tANI_U16            aid;
    tANI_U16            transId;
    tANI_U8             retryNum;

    pHdr = WDA_GET_RX_MAC_HEADER(pRxPacketInfo);
    frameLen = WDA_GET_RX_PAYLOAD_LEN(pRxPacketInfo);
    pBody = WDA_GET_RX_MPDU_DATA(pRxPacketInfo);
    VOS_TRACE(VOS_MODULE_ID_PE, VOS_TRACE_LEVEL_INFO,
                         ("SA Query Response received...")) ;

    /* When a station, supplicant handles SA Query Response.
     * Forward to SME to HDD to wpa_supplicant.
     */
    if (LIM_IS_STA_ROLE(psessionEntry)) {
        limSendSmeMgmtFrameInd(pMac, pHdr->fc.subType, (tANI_U8*)pHdr,
                               frameLen + sizeof(tSirMacMgmtHdr), 0,
                               WDA_GET_RX_CH( pRxPacketInfo ),
                               psessionEntry,
                               WDA_GET_RX_RSSI_NORMALIZED(pRxPacketInfo),
                               RXMGMT_FLAG_NONE);
        return;
    }

    /* If this is an unprotected SA Query Response, then ignore it. */
    if (pHdr->fc.wep == 0)
        return;

    pSta = dphLookupHashEntry(pMac, pHdr->sa, &aid, &psessionEntry->dph.dphHashTable);
    if (NULL == pSta)
        return;

    limLog(pMac, LOG1,
           FL("SA Query Response source addr - %0x:%0x:%0x:%0x:%0x:%0x"),
           pHdr->sa[0], pHdr->sa[1], pHdr->sa[2], pHdr->sa[3],
           pHdr->sa[4], pHdr->sa[5]);
    limLog(pMac, LOG1,
           FL("SA Query state for station - %d"), pSta->pmfSaQueryState);

    if (DPH_SA_QUERY_IN_PROGRESS != pSta->pmfSaQueryState)
        return;

    /* Extract 11w trsansId from SA query reponse action frame
       In SA query response action frame:
          Category       : 1 byte
          Action         : 1 byte
          Transaction ID : 2 bytes */
    vos_mem_copy(&transId, &pBody[2], 2);

    /* If SA Query is in progress with the station and the station
       responds then the association request that triggered the SA
       query is from a rogue station, just go back to initial state. */
    for (retryNum = 0; retryNum <= pSta->pmfSaQueryRetryCount; retryNum++)
        if (transId == pSta->pmfSaQueryStartTransId + retryNum)
        {
            limLog(pMac, LOG1,
                   FL("Found matching SA Query Request - transaction ID %d"), transId);
            tx_timer_deactivate(&pSta->pmfSaQueryTimer);
            pSta->pmfSaQueryState = DPH_SA_QUERY_NOT_IN_PROGRESS;
            break;
        }
}
#endif

#ifdef WLAN_FEATURE_11W
/**
 * limDropUnprotectedActionFrame
 *
 *FUNCTION:
 * This function checks if an Action frame should be dropped since it is
 * a Robust Managment Frame, it is unprotected, and it is received on a
 * connection where PMF is enabled.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param  pMac - Global MAC structure
 * @param  psessionEntry - PE session entry
 * @param  pHdr - Frame header
 * @param  category - Action frame category
 * @return TRUE if frame should be dropped
 */

static tANI_BOOLEAN
limDropUnprotectedActionFrame (tpAniSirGlobal pMac, tpPESession psessionEntry,
                               tpSirMacMgmtHdr pHdr, tANI_U8 category)
{
    tANI_U16 aid;
    tpDphHashNode pStaDs;
    tANI_BOOLEAN rmfConnection = eANI_BOOLEAN_FALSE;

    if (LIM_IS_AP_ROLE(psessionEntry) || LIM_IS_BT_AMP_AP_ROLE(psessionEntry)) {
        pStaDs = dphLookupHashEntry(pMac, pHdr->sa, &aid, &psessionEntry->dph.dphHashTable);
        if (pStaDs != NULL)
            if (pStaDs->rmfEnabled)
                rmfConnection = eANI_BOOLEAN_TRUE;
    } else if (psessionEntry->limRmfEnabled)
        rmfConnection = eANI_BOOLEAN_TRUE;

    if (rmfConnection && (pHdr->fc.wep == 0))
    {
        PELOGE(limLog(pMac, LOGE, FL("Dropping unprotected Action category %d frame "
                                     "since RMF is enabled."), category);)
        return eANI_BOOLEAN_TRUE;
    }
    else
        return eANI_BOOLEAN_FALSE;
}
#endif

/**
 * limProcessActionFrame
 *
 *FUNCTION:
 * This function is called by limProcessMessageQueue() upon
 * Action frame reception.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param  pMac - Pointer to Global MAC structure
 * @param  *pRxPacketInfo - A pointer to packet info structure
 * @return None
 */

void
limProcessActionFrame(tpAniSirGlobal pMac, tANI_U8 *pRxPacketInfo,tpPESession psessionEntry)
{
    tANI_U8 *pBody = WDA_GET_RX_MPDU_DATA(pRxPacketInfo);
    tpSirMacActionFrameHdr pActionHdr = (tpSirMacActionFrameHdr) pBody;
    tANI_U32         frameLen = WDA_GET_RX_PAYLOAD_LEN(pRxPacketInfo);
    tpSirMacMgmtHdr pHdr = WDA_GET_RX_MAC_HEADER(pRxPacketInfo);

    if (frameLen < sizeof(*pActionHdr)) {
        limLog(pMac, LOGE,
               FL("frame_len %d less than Action Frame Hdr size"),
               frameLen);
        return;
    }

#ifdef WLAN_FEATURE_11W
    if (lim_is_robust_mgmt_action_frame(pActionHdr->category) &&
        limDropUnprotectedActionFrame(pMac, psessionEntry, pHdr,
                                          pActionHdr->category)) {
        limLog(pMac, LOGE,
            FL("Don't send unprotect action frame to upper layer categ %d "),
                                                    pActionHdr->category);
        return;
    }
#endif

    switch (pActionHdr->category)
    {
        /*
         * WARNING: If you add Action frame category case here, set the
         * corresponding bit to 1 in sme_set_allowed_action_frames() for
         * the FW to hand over that frame to host without dropping itself
         */
        case SIR_MAC_ACTION_QOS_MGMT:
            if ( (psessionEntry->limQosEnabled) ||
                  (pActionHdr->actionID == SIR_MAC_QOS_MAP_CONFIGURE) )
            {
                switch (pActionHdr->actionID)
                {
                    case SIR_MAC_QOS_ADD_TS_REQ:
                        __limProcessAddTsReq(pMac, (tANI_U8 *) pRxPacketInfo,psessionEntry);
                        break;

                    case SIR_MAC_QOS_ADD_TS_RSP:
                        __limProcessAddTsRsp(pMac, (tANI_U8 *) pRxPacketInfo,psessionEntry);
                        break;

                    case SIR_MAC_QOS_DEL_TS_REQ:
                        __limProcessDelTsReq(pMac, (tANI_U8 *) pRxPacketInfo,psessionEntry);
                        break;

                    case SIR_MAC_QOS_MAP_CONFIGURE:
                        __limProcessQosMapConfigureFrame(pMac,
                                   (tANI_U8 *) pRxPacketInfo, psessionEntry);
                    break;
                    default:
                        limLog(pMac, LOG1,
                          FL("Qos action %d not handled"),
                          pActionHdr->actionID);
                        break;
                }
                break ;
            }

           break;

        case SIR_MAC_ACTION_SPECTRUM_MGMT:
            switch (pActionHdr->actionID)
            {
                case SIR_MAC_ACTION_CHANNEL_SWITCH_ID:
                    if (LIM_IS_STA_ROLE(psessionEntry)) {
                        __limProcessChannelSwitchActionFrame(pMac,
                                                             pRxPacketInfo,
                                                             psessionEntry);
                    }
                    break;
                default:
                    limLog(pMac, LOG1,
                      FL("Spectrum mgmt action id %d not handled"),
                      pActionHdr->actionID);
                    break;
            }
            break;

        case SIR_MAC_ACTION_WME:
            if (! psessionEntry->limWmeEnabled)
            {
                limLog(pMac, LOGW, FL("WME mode disabled - dropping action frame %d"),
                       pActionHdr->actionID);
                break;
            }
            switch(pActionHdr->actionID)
            {
                case SIR_MAC_QOS_ADD_TS_REQ:
                    __limProcessAddTsReq(pMac, (tANI_U8 *) pRxPacketInfo,psessionEntry);
                    break;

                case SIR_MAC_QOS_ADD_TS_RSP:
                    __limProcessAddTsRsp(pMac, (tANI_U8 *) pRxPacketInfo,psessionEntry);
                    break;

                case SIR_MAC_QOS_DEL_TS_REQ:
                    __limProcessDelTsReq(pMac, (tANI_U8 *) pRxPacketInfo,psessionEntry);
                    break;

                case SIR_MAC_QOS_MAP_CONFIGURE:
                    __limProcessQosMapConfigureFrame(pMac,
                                     (tANI_U8 *) pRxPacketInfo, psessionEntry);
                    break;

                default:
                    limLog(pMac, LOG1,
                      FL("WME action %d not handled"),
                      pActionHdr->actionID);
                    break;
            }
            break;

    case SIR_MAC_ACTION_HT:
        /** Type of HT Action to be performed*/
        switch(pActionHdr->actionID) {
        case SIR_MAC_SM_POWER_SAVE:
            if (LIM_IS_AP_ROLE(psessionEntry))
                __limProcessSMPowerSaveUpdate(pMac, (tANI_U8 *) pRxPacketInfo,psessionEntry);
            break;
        default:
            limLog(pMac, LOG1,
              FL("Action ID %d not handled in HT Action category"),
              pActionHdr->actionID);
            break;
        }
        break;

    case SIR_MAC_ACTION_WNM:
    {
        limLog(pMac, LOG1, FL("WNM Action category %d action %d."),
                                pActionHdr->category, pActionHdr->actionID);
        switch (pActionHdr->actionID)
        {
            case SIR_MAC_WNM_BSS_TM_QUERY:
            case SIR_MAC_WNM_BSS_TM_REQUEST:
            case SIR_MAC_WNM_BSS_TM_RESPONSE:
            case SIR_MAC_WNM_NOTIF_REQUEST:
            case SIR_MAC_WNM_NOTIF_RESPONSE:
            {
               tANI_S8 rssi = WDA_GET_RX_RSSI_NORMALIZED(pRxPacketInfo);

               /* Forward to the SME to HDD to wpa_supplicant */
               limSendSmeMgmtFrameInd(pMac, pHdr->fc.subType, (tANI_U8*)pHdr,
                       frameLen + sizeof(tSirMacMgmtHdr),
                       psessionEntry->smeSessionId,
                       WDA_GET_RX_CH( pRxPacketInfo ),
                       psessionEntry, rssi, RXMGMT_FLAG_NONE);
               break;
            }
            default:
            limLog(pMac, LOG1,
                 FL("Action ID %d not handled in WNM Action category"),
                                                pActionHdr->actionID);
            break;
        }
        break;
    }
#if defined WLAN_FEATURE_VOWIFI
    case SIR_MAC_ACTION_RRM:
        /* Ignore RRM measurement request until DHCP is set */
        if (pMac->rrm.rrmPEContext.rrmEnable &&
           pMac->roam.roamSession[psessionEntry->smeSessionId].dhcp_done)
        {
            switch(pActionHdr->actionID) {
                case SIR_MAC_RRM_RADIO_MEASURE_REQ:
                    __limProcessRadioMeasureRequest( pMac, (tANI_U8 *) pRxPacketInfo, psessionEntry );
                    break;
                case SIR_MAC_RRM_LINK_MEASUREMENT_REQ:
                    __limProcessLinkMeasurementReq( pMac, (tANI_U8 *) pRxPacketInfo, psessionEntry );
                    break;
                case SIR_MAC_RRM_NEIGHBOR_RPT:
                    __limProcessNeighborReport( pMac, (tANI_U8*) pRxPacketInfo, psessionEntry );
                    break;
                default:
                    limLog(pMac, LOG1,
                      FL("Action ID %d not handled in RRM"),
                      pActionHdr->actionID);
                    break;

            }
        }
        else
        {
            /* Else we will just ignore the RRM messages.*/
            limLog(pMac, LOG1,
              FL("RRM Action frame ignored as rrmEnable is %d or DHCP not completed %d"),
              pMac->rrm.rrmPEContext.rrmEnable,
              pMac->roam.roamSession[psessionEntry->smeSessionId].dhcp_done);
        }
        break;
#endif
#if  defined (WLAN_FEATURE_VOWIFI_11R) || defined (FEATURE_WLAN_ESE) || defined(FEATURE_WLAN_LFR)
        case SIR_MAC_ACTION_VENDOR_SPECIFIC_CATEGORY:
            {
              tpSirMacVendorSpecificFrameHdr pVendorSpecific = (tpSirMacVendorSpecificFrameHdr) pActionHdr;
              tANI_U8 Oui[] = { 0x00, 0x00, 0xf0 };

              if (frameLen < sizeof(*pVendorSpecific)) {
                  limLog(pMac, LOGE, FL("frame len %d less than Vendor Specific Hdr len"),
                         frameLen);
                         break;
              }
              //Check if it is a vendor specific action frame.
              if (LIM_IS_STA_ROLE(psessionEntry) &&
                  (VOS_TRUE == vos_mem_compare(psessionEntry->selfMacAddr,
                    &pHdr->da[0], sizeof(tSirMacAddr))) &&
                    IS_WES_MODE_ENABLED(pMac) &&
                    vos_mem_compare(pVendorSpecific->Oui, Oui, 3)) {
                  PELOGE( limLog( pMac, LOGW, FL("Received Vendor specific action frame, OUI %x %x %x"),
                         pVendorSpecific->Oui[0], pVendorSpecific->Oui[1], pVendorSpecific->Oui[2]);)
                 /* Forward to the SME to HDD to wpa_supplicant */
                 // type is ACTION
                 limSendSmeMgmtFrameInd(pMac, pHdr->fc.subType,
                    (tANI_U8*)pHdr, frameLen + sizeof(tSirMacMgmtHdr),
                    psessionEntry->smeSessionId,
                    WDA_GET_RX_CH( pRxPacketInfo ), psessionEntry, 0,
                    RXMGMT_FLAG_NONE);
              }
              else {
                 limLog(pMac, LOG1, FL("Dropping the vendor specific action frame because of( "
                                        "WES Mode not enabled (WESMODE = %d) or OUI mismatch (%02x %02x %02x) or "
                                        "not received with SelfSta Mac address) system role = %d"),
                                        IS_WES_MODE_ENABLED(pMac),
                                        pVendorSpecific->Oui[0],
                                        pVendorSpecific->Oui[1],
                                        pVendorSpecific->Oui[2],
                                        GET_LIM_SYSTEM_ROLE(psessionEntry));
              }
           }
           break;
#endif /* WLAN_FEATURE_VOWIFI_11R || FEATURE_WLAN_ESE ||
          FEATURE_WLAN_LFR */
    case SIR_MAC_ACTION_PUBLIC_USAGE:
        switch(pActionHdr->actionID) {
        case SIR_MAC_ACTION_VENDOR_SPECIFIC:
            {
              tpSirMacVendorSpecificPublicActionFrameHdr pPubAction = (tpSirMacVendorSpecificPublicActionFrameHdr) pActionHdr;
              tANI_U8 P2POui[] = { 0x50, 0x6F, 0x9A, 0x09 };

              if (frameLen < sizeof(*pPubAction)) {
                limLog(pMac, LOG1,
                  FL("Received action frame of invalid len %d"), frameLen);
                break;
              }

              //Check if it is a P2P public action frame.
              if (vos_mem_compare(pPubAction->Oui, P2POui, 4))
              {
                 /* Forward to the SME to HDD to wpa_supplicant */
                 // type is ACTION
                 limSendSmeMgmtFrameInd(pMac, pHdr->fc.subType,
                    (tANI_U8*)pHdr, frameLen + sizeof(tSirMacMgmtHdr),
                    psessionEntry->smeSessionId,
                    WDA_GET_RX_CH( pRxPacketInfo ), psessionEntry,
                    WDA_GET_RX_RSSI_NORMALIZED(pRxPacketInfo),
                    RXMGMT_FLAG_NONE);
              }
              else
              {
                 limLog(pMac, LOG1,
                      FL("Unhandled public action frame (Vendor specific). OUI %x %x %x %x"),
                      pPubAction->Oui[0], pPubAction->Oui[1],
                      pPubAction->Oui[2], pPubAction->Oui[3]);
              }
           }
            break;

         case SIR_MAC_ACTION_2040_BSS_COEXISTENCE:
           {
              limSendSmeMgmtFrameInd(pMac, pHdr->fc.subType,
                    (tANI_U8*)pHdr, frameLen + sizeof(tSirMacMgmtHdr),
                    psessionEntry->smeSessionId,
                    WDA_GET_RX_CH( pRxPacketInfo ), psessionEntry,
                    WDA_GET_RX_RSSI_NORMALIZED(pRxPacketInfo),
                    RXMGMT_FLAG_NONE);
            }
            break;
#ifdef FEATURE_WLAN_TDLS
           case SIR_MAC_TDLS_DIS_RSP:
           {
               tANI_S8             rssi;

               rssi = WDA_GET_RX_RSSI_NORMALIZED(pRxPacketInfo);

               VOS_TRACE(VOS_MODULE_ID_PE, VOS_TRACE_LEVEL_INFO,
                                    ("Public Action TDLS Discovery RSP ..")) ;
               limSendSmeMgmtFrameInd(pMac, pHdr->fc.subType,
                  (tANI_U8*)pHdr, frameLen + sizeof(tSirMacMgmtHdr),
                  psessionEntry->smeSessionId,
                  WDA_GET_RX_CH( pRxPacketInfo ), psessionEntry, rssi,
                  RXMGMT_FLAG_NONE);
           }
               break;
#endif

        case SIR_MAC_ACTION_EXT_CHANNEL_SWITCH_ID:
           lim_process_ext_channel_switch_action_frame(pMac,
                                pRxPacketInfo, psessionEntry);
            break;
        default:
            limLog(pMac, LOG1,
              FL("Unhandled public action frame -- %x "),
              pActionHdr->actionID);
            break;
        }
        break;

#ifdef WLAN_FEATURE_11W
    case SIR_MAC_ACTION_SA_QUERY:
    {
        PELOGE(limLog(pMac, LOG1, FL("SA Query Action category %d action %d."), pActionHdr->category, pActionHdr->actionID);)
        switch (pActionHdr->actionID)
        {
            case  SIR_MAC_SA_QUERY_REQ:
                /**11w SA query request action frame received**/
                /* Respond directly to the incoming request in LIM */
                __limProcessSAQueryRequestActionFrame(pMac,(tANI_U8*) pRxPacketInfo, psessionEntry );
                break;
            case  SIR_MAC_SA_QUERY_RSP:
                /**11w SA query response action frame received**/
                /* Handle based on the current SA Query state */
                __limProcessSAQueryResponseActionFrame(pMac,(tANI_U8*) pRxPacketInfo, psessionEntry );
                break;
            default:
                break;
        }
        break;
     }
#endif
#ifdef WLAN_FEATURE_11AC
    case SIR_MAC_ACTION_VHT:
    {
        if (psessionEntry->vhtCapability)
        {
            switch (pActionHdr->actionID)
            {
                case  SIR_MAC_VHT_OPMODE_NOTIFICATION:
                    __limProcessOperatingModeActionFrame(pMac,pRxPacketInfo,psessionEntry);
                break;
                case  SIR_MAC_VHT_GID_NOTIFICATION:
                    /* Only if ini supports it */
                    if (psessionEntry->enableVhtGid)
                      __limProcessGidManagementActionFrame(pMac,pRxPacketInfo,psessionEntry);
                break;
                default:
                break;
            }
        }
        break;
    }
#endif
    case SIR_MAC_ACTION_FST:
    {
        tpSirMacMgmtHdr     pHdr;

        pHdr = WDA_GET_RX_MAC_HEADER(pRxPacketInfo);

        limLog(pMac, LOG1, FL("Received FST MGMT action frame"));
        /* Forward to the SME to HDD */
        limSendSmeMgmtFrameInd(pMac, pHdr->fc.subType, (tANI_U8*)pHdr,
                               frameLen + sizeof(tSirMacMgmtHdr),
                               psessionEntry->smeSessionId,
                               WDA_GET_RX_CH(pRxPacketInfo),
                               psessionEntry,
                               WDA_GET_RX_RSSI_NORMALIZED(pRxPacketInfo),
                               RXMGMT_FLAG_NONE);
        break;
    }
    default:
       limLog(pMac, LOGE,
         FL("Action category %d not handled"),
         pActionHdr->category);
       break;
    }
}

/**
 * limProcessActionFrameNoSession
 *
 *FUNCTION:
 * This function is called by limProcessMessageQueue() upon
 * Action frame reception and no session.
 * Currently only public action frames can be received from
 * a non-associated station.
 *
 *LOGIC:
 *
 *ASSUMPTIONS:
 *
 *NOTE:
 *
 * @param  pMac - Pointer to Global MAC structure
 * @param  *pBd - A pointer to Buffer descriptor + associated PDUs
 * @return None
 */

void
limProcessActionFrameNoSession(tpAniSirGlobal pMac, tANI_U8 *pBd)
{
   tANI_U8 *pBody = WDA_GET_RX_MPDU_DATA(pBd);
   tpSirMacVendorSpecificPublicActionFrameHdr pActionHdr = (tpSirMacVendorSpecificPublicActionFrameHdr) pBody;
   tANI_U32 frameLen = WDA_GET_RX_PAYLOAD_LEN(pBd);

   limLog( pMac, LOG1, "Received a Action frame -- no session");

   if (frameLen < sizeof(*pActionHdr)) {
     limLog(pMac, LOGE,
       FL("Received action frame of invalid len %d"), frameLen);
     return;
   }

   switch ( pActionHdr->category )
   {
      case SIR_MAC_ACTION_PUBLIC_USAGE:
         switch(pActionHdr->actionID) {
            case SIR_MAC_ACTION_VENDOR_SPECIFIC:
              {
                tpSirMacMgmtHdr     pHdr;
                tANI_U8 P2POui[] = { 0x50, 0x6F, 0x9A, 0x09 };
                tANI_U8 DPPOui[] = { 0x50, 0x6F, 0x9A, 0x1A };

                pHdr = WDA_GET_RX_MAC_HEADER(pBd);

                //Check if it is a P2P public action frame.
                if (vos_mem_compare(pActionHdr->Oui, P2POui, 4))
                {
                  /* Forward to the SME to HDD to wpa_supplicant */
                  // type is ACTION
                  limSendSmeMgmtFrameInd(pMac, pHdr->fc.subType,
                      (tANI_U8*)pHdr, frameLen + sizeof(tSirMacMgmtHdr), 0,
                      WDA_GET_RX_CH( pBd ), NULL, WDA_GET_RX_RSSI_RAW(pBd),
                      RXMGMT_FLAG_NONE);
                } else if (vos_mem_compare(pActionHdr->Oui, DPPOui, 4))
                {
                  limSendSmeMgmtFrameInd(pMac, pHdr->fc.subType,
                      (tANI_U8*)pHdr, frameLen + sizeof(tSirMacMgmtHdr), 0,
                      WDA_GET_RX_CH( pBd ), NULL, WDA_GET_RX_RSSI_RAW(pBd),
                      RXMGMT_FLAG_NONE);
                }
                else
                {
                  limLog(pMac, LOG1,
                    FL("Unhandled public action frame (Vendor specific). OUI %x %x %x %x"),
                      pActionHdr->Oui[0], pActionHdr->Oui[1],
                      pActionHdr->Oui[2], pActionHdr->Oui[3]);
                }
              }
               break;
            default:
               limLog(pMac, LOG1,
                 FL("Unhandled public action frame -- %x "),
                 pActionHdr->actionID);
               break;
         }
         break;
      /* Handle vendor specific action */
      case SIR_MAC_ACTION_VENDOR_SPECIFIC_CATEGORY:
      {
          tpSirMacMgmtHdr     header;

          header = WDA_GET_RX_MAC_HEADER(pBd);
          limSendSmeMgmtFrameInd(pMac, header->fc.subType,
              (uint8_t*)header, frameLen + sizeof(tSirMacMgmtHdr), 0,
              WDA_GET_RX_CH(pBd), NULL, WDA_GET_RX_RSSI_RAW(pBd),
              RXMGMT_FLAG_NONE);
          break;
      }
      default:
         limLog(pMac, LOG1,
             FL("Unhandled action frame without session -- %x "),
             pActionHdr->category);
            break;

   }
}
