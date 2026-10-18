import {
	type CCEncodingContext,
	FirmwareUpdateMetaDataCC,
	FirmwareUpdateMetaDataCCReport,
	Security2CCMessageEncapsulation,
} from "@zwave-js/cc";
import { SecurityClass, SecurityManager2 } from "@zwave-js/core";
import { Bytes } from "@zwave-js/shared";
import { expect, test } from "vitest";

import { getFirmwareUpdateFragmentSize } from "./70_FirmwareUpdate.js";

test.each([46, 48, 54])(
	"firmware fragments fit a %i-byte frame even when S2 resynchronizes",
	async (frameSize) => {
		const securityClass = SecurityClass.S2_Authenticated;
		const securityManager2 = await SecurityManager2.create();
		await securityManager2.setKey(securityClass, new Bytes(16).fill(1));
		securityManager2.storeRemoteEI(2, new Bytes(16).fill(2));
		const context: CCEncodingContext = {
			ownNodeId: 1,
			homeId: 0x12345678,
			securityManager: undefined,
			securityManager2,
			securityManagerLR: undefined,
			getDeviceConfig: () => undefined,
			getSupportedCCVersion: () => 5,
			getHighestSecurityClass: () => securityClass,
			hasSecurityClass: (_id, sc) => sc === securityClass,
			setSecurityClass: () => {},
		};
		const overhead = new Security2CCMessageEncapsulation({
			nodeId: 2,
			encapsulated: new FirmwareUpdateMetaDataCC({ nodeId: 2 }),
		});
		const capacity = overhead.getMaxPayloadLength(frameSize) - 4;
		const fragmentSize = getFirmwareUpdateFragmentSize(
			capacity,
			20,
			securityClass,
		);
		const message = new Security2CCMessageEncapsulation({
			nodeId: 2,
			encapsulated: new FirmwareUpdateMetaDataCCReport({
				nodeId: 2,
				reportNumber: 1,
				isLast: false,
				firmwareData: new Bytes(fragmentSize).fill(3),
			}),
		});
		const serialized = await message.serialize(context);
		expect(serialized[3] & 1).toBe(1);
		expect(serialized.length).toBeLessThanOrEqual(frameSize);
		expect(fragmentSize).toBeLessThanOrEqual(20);
		expect(fragmentSize).toBeGreaterThan(0);
		// The node's smaller advertised limit still takes precedence.
		expect(getFirmwareUpdateFragmentSize(capacity, 5, securityClass)).toBe(
			5,
		);
	},
);

test.each([SecurityClass.None, SecurityClass.S0_Legacy])(
	"fragment limits remain unchanged for security class %s",
	(securityClass) => {
		expect(getFirmwareUpdateFragmentSize(28, 20, securityClass)).toBe(20);
		expect(getFirmwareUpdateFragmentSize(16, 20, securityClass)).toBe(16);
	},
);
