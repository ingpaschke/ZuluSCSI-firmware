/*
 * Copyright (c) 2023-2026 joshua stein <jcs@jcs.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef ZULUSCSI_NETWORK

#include <string.h>
#include "scsi.h"
#include "scsi2sd_time.h"
#include "scsiPhy.h"
#include "config.h"
#include "network.h"
#include "crc32_ethernet.h"

extern int platform_network_send(uint8_t *buf, size_t len);

bool scsiNetworkEnabled = false;
struct scsiNetworkPacketQueue scsiNetworkInboundQueue;
/* Frames the radio delivered that the ring had no room for; the
 * DaynaPORT statistics command reports and clears them. */
uint32_t scsiNetworkMissed = 0;

struct __attribute__((packed)) wifi_network_entry wifi_network_list[WIFI_NETWORK_LIST_ENTRY_COUNT] = { 0 };

void scsiNetworkWifiScan(void)
{
	// initiate wi-fi scan
	scsiDev.dataLen = 1;
	int ret = platform_network_wifi_start_scan();
	scsiDev.data[0] = (ret < 0 ? ret : 1);
	scsiDev.phase = DATA_IN;
}

void scsiNetworkWifiComplete(void)
{
	// check for wi-fi scan completion
	scsiDev.dataLen = 1;
	scsiDev.data[0] = (platform_network_wifi_scan_finished() ? 1 : 0);
	scsiDev.phase = DATA_IN;
}

void scsiNetworkWifiScanResults(uint32_t size)
{
	// return wi-fi scan results
	if (!platform_network_wifi_scan_finished())
	{
		scsiDev.target->sense.code = ILLEGAL_REQUEST;
		scsiDev.target->sense.asc = INVALID_FIELD_IN_CDB;
		scsiDev.status = CHECK_CONDITION;
		scsiDev.phase = STATUS;
		return;
	}

	if (unlikely(size < 2))
	{
		scsiDev.target->sense.code = ILLEGAL_REQUEST;
		scsiDev.target->sense.asc = INVALID_FIELD_IN_CDB;
		scsiDev.status = CHECK_CONDITION;
		scsiDev.phase = STATUS;
		return;
	}

	int nets = 0;
	for (int i = 0; i < WIFI_NETWORK_LIST_ENTRY_COUNT; i++)
	{
		if (wifi_network_list[i].ssid[0] == '\0')
			break;
		nets++;
	}

	if (nets) {
		unsigned int netsize = sizeof(struct wifi_network_entry) * nets;
		if (netsize + 2 > sizeof(scsiDev.data))
		{
			LOGMSG_F("WARNING: wifi_network_list is bigger than scsiDev.data, truncating", 0);
			netsize = sizeof(scsiDev.data) - 2;
			netsize -= (netsize % (sizeof(struct wifi_network_entry)));
		}
		if (netsize + 2 > size)
		{
			LOGMSG_F("WARNING: wifi_network_list is bigger than requested dataLen, truncating", 0);
			netsize = size - 2;
			netsize -= (netsize % (sizeof(struct wifi_network_entry)));
		}
		scsiDev.data[0] = (netsize >> 8) & 0xff;
		scsiDev.data[1] = netsize & 0xff;
		memcpy(scsiDev.data + 2, wifi_network_list, netsize);
		scsiDev.dataLen = netsize + 2;
	}
	else
	{
		scsiDev.data[0] = 0;
		scsiDev.data[1] = 0;
		scsiDev.dataLen = 2;
	}

	scsiDev.phase = DATA_IN;
}

void scsiNetworkWifiInfo(void)
{
	// return current wi-fi information
	struct wifi_network_entry wifi_cur = { 0 };
	int entrysize = sizeof(wifi_cur);

	char *ssid = platform_network_wifi_ssid();
	if (ssid != NULL)
		strlcpy(wifi_cur.ssid, ssid, sizeof(wifi_cur.ssid));

	char *bssid = platform_network_wifi_bssid();
	if (bssid != NULL)
		memcpy(wifi_cur.bssid, bssid, sizeof(wifi_cur.bssid));

	wifi_cur.rssi = platform_network_wifi_rssi();

	wifi_cur.channel = platform_network_wifi_channel();

	scsiDev.data[0] = (entrysize >> 8) & 0xff;
	scsiDev.data[1] = entrysize & 0xff;
	memcpy(scsiDev.data + 2, (char *)&wifi_cur, entrysize);
	scsiDev.dataLen = entrysize + 2;
	scsiDev.phase = DATA_IN;
}

void scsiNetworkWifiJoin(uint32_t size)
{
	// set current wi-fi network
	struct wifi_join_request req = { 0 };

	if (size != sizeof(req)) {
		LOGMSG_F("wifi_join_request bad size (%zu != %zu), ignoring", size, sizeof(req));
		scsiDev.status = CHECK_CONDITION;
		scsiDev.phase = STATUS;
		return;
	}

	int parityError = 0;
	scsiEnterPhase(DATA_OUT);
	scsiRead((uint8_t *)&req, sizeof(req), &parityError);
	DBGMSG_F("%s: read join request from host:", __func__);
	DBGMSG_BUF(scsiDev.data, size);
	platform_network_wifi_join(req.ssid, req.key, false);

	scsiDev.status = GOOD;
	scsiDev.phase = STATUS;
}

/*
 * The DaynaPORT protocol itself now lives in DaynaPort/sl003_core.c,
 * built from the Dayna SL003 v2.0 ROM disassembly and shared with the
 * BlueSCSI-SL003 fork; DaynaPort/DaynaPort.c drives it over this
 * platform's bus and owns scsiNetworkCommand().
 *
 * What stays here is the ZuluSCSI WiFi extension: several
 * configuration commands sharing one vendor opcode, with the
 * sub-command in CDB[1]. Each helper sets the data phase itself.
 */
int scsiNetworkWifiCommand(void)
{
	uint32_t size = (scsiDev.cdb[3] << 8) + scsiDev.cdb[4];

	DBGMSG_F("------ wi-fi command 0x%02x (size %d)", scsiDev.cdb[1], size);

	switch (scsiDev.cdb[1]) {
	case SCSI_NETWORK_WIFI_CMD_SCAN:
		scsiNetworkWifiScan();
		break;
	case SCSI_NETWORK_WIFI_CMD_COMPLETE:
		scsiNetworkWifiComplete();
		break;
	case SCSI_NETWORK_WIFI_CMD_SCAN_RESULTS:
		scsiNetworkWifiScanResults(size);
		break;
	case SCSI_NETWORK_WIFI_CMD_INFO:
		scsiNetworkWifiInfo();
		break;
	case SCSI_NETWORK_WIFI_CMD_JOIN:
		scsiNetworkWifiJoin(size);
		break;
	}

	return 1;
}

int scsiNetworkEnqueue(const uint8_t *buf, size_t len)
{
	uint8_t nextWriteIndex;

	if (!scsiNetworkEnabled)
		return 0;

	if (len + 4 > sizeof(scsiNetworkInboundQueue.packets[0]))
	{
		DBGMSG_F("%s: dropping incoming network packet, too large (%zu > %zu)", __func__, len, sizeof(scsiNetworkInboundQueue.packets[0]));
		return 0;
	}

	memcpy(scsiNetworkInboundQueue.packets[scsiNetworkInboundQueue.writeIndex], buf, len);

	if (len < 60) {
		// packets the host reads have to be at least 64 bytes, so pad before we CRC and add to queue
		memset(scsiNetworkInboundQueue.packets[scsiNetworkInboundQueue.writeIndex] + len, 0, 60 - len);
		len += (60 - len);
	}

	uint32_t crc = crc32(scsiNetworkInboundQueue.packets[scsiNetworkInboundQueue.writeIndex], len);
	scsiNetworkInboundQueue.packets[scsiNetworkInboundQueue.writeIndex][len] = crc & 0xff;
	scsiNetworkInboundQueue.packets[scsiNetworkInboundQueue.writeIndex][len + 1] = (crc >> 8) & 0xff;
	scsiNetworkInboundQueue.packets[scsiNetworkInboundQueue.writeIndex][len + 2] = (crc >> 16) & 0xff;
	scsiNetworkInboundQueue.packets[scsiNetworkInboundQueue.writeIndex][len + 3] = (crc >> 24) & 0xff;

	scsiNetworkInboundQueue.sizes[scsiNetworkInboundQueue.writeIndex] = len + 4;

	/*
	 * Publish only if a slot remains. Letting writeIndex land on
	 * readIndex makes a full ring read as an EMPTY one, so the whole
	 * backlog goes missing at once and the slot the consumer is reading
	 * from is the next one overwritten. Drop the newest frame instead
	 * and count it: Ethernet may lose a frame, but the queue must not
	 * lose the ones already in it.
	 */
	nextWriteIndex = (scsiNetworkInboundQueue.writeIndex == NETWORK_PACKET_QUEUE_SIZE - 1)
	               ? 0 : (uint8_t)(scsiNetworkInboundQueue.writeIndex + 1);

	if (nextWriteIndex == scsiNetworkInboundQueue.readIndex)
	{
		DBGMSG_F("%s: receive ring full, dropping frame", __func__);
		scsiNetworkMissed++;
		return 0;
	}

	scsiNetworkInboundQueue.writeIndex = nextWriteIndex;

	return 1;
}

#endif // ZULUSCSI_NETWORK
