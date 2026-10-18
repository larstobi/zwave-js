import {
	SecurityClass,
	SecurityManager2,
	SPANState,
	ZWaveError,
	ZWaveErrorCodes,
} from "@zwave-js/core";
import { Bytes } from "@zwave-js/shared";
import { expect, test } from "vitest";

import { Security2CCAPI } from "./Security2CC.js";

test.each(["unchanged", "local", "remote", "established"])(
	"a late NonceReport transmission failure preserves %s security state",
	async (replacement) => {
		const securityManager2 = await SecurityManager2.create();
		await securityManager2.setKey(
			SecurityClass.S2_Authenticated,
			new Bytes(16).fill(1),
		);
		let fail!: (error: Error) => void;
		let sent!: () => void;
		const pending = new Promise<void>((_, reject) => {
			fail = reject;
		});
		const started = new Promise<void>((resolve) => {
			sent = resolve;
		});
		const api = new Security2CCAPI(
			{
				ownNodeId: 1,
				securityManager2,
				sendCommand: async () => {
					sent();
					await pending;
				},
			} as unknown as ConstructorParameters<typeof Security2CCAPI>[0],
			{
				nodeId: 128,
				index: 0,
				virtual: false,
			} as ConstructorParameters<typeof Security2CCAPI>[1],
		);
		const sending = api.sendNonce();
		await started;
		if (replacement === "local") {
			await securityManager2.generateNonce(128);
		} else if (replacement === "remote") {
			securityManager2.storeRemoteEI(128, new Bytes(16).fill(2));
		} else if (replacement === "established") {
			await securityManager2.initializeSPAN(
				128,
				SecurityClass.S2_Authenticated,
				new Bytes(16).fill(2),
				new Bytes(16).fill(3),
			);
		}
		const current = securityManager2.getSPANState(128);
		securityManager2.storeSequenceNumber(128, 123);
		fail(
			new ZWaveError(
				"Late NoAck",
				ZWaveErrorCodes.Controller_MessageDropped,
			),
		);
		expect(await sending).toBe(false);
		if (replacement === "unchanged") {
			expect(securityManager2.getSPANState(128).type).toBe(
				SPANState.None,
			);
		} else {
			expect(securityManager2.getSPANState(128)).toBe(current);
			expect(securityManager2.isDuplicateSinglecast(128, 123)).toBe(true);
		}
	},
);
