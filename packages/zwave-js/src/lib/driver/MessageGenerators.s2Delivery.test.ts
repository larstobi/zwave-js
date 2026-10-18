import {
	type CCEncodingContext,
	CommandClass,
	FirmwareUpdateMetaDataCCReport,
	Security2CCMessageEncapsulation,
	Security2CCNonceReport,
} from "@zwave-js/cc";
import { FirmwareUpdateMetaDataCCAPI } from "@zwave-js/cc/FirmwareUpdateMetaDataCC";
import {
	SecurityClass,
	SecurityManager2,
	TransmitStatus,
	ZWaveErrorCodes,
} from "@zwave-js/core";
import {
	SendDataBridgeRequest,
	SendDataBridgeRequestTransmitReport,
} from "@zwave-js/serial/serialapi";
import { Bytes } from "@zwave-js/shared";
import { afterEach, expect, test, vi } from "vitest";

import { Driver } from "./Driver.js";
import { secureMessageGeneratorS2 } from "./MessageGenerators.js";

afterEach(() => {
	vi.useRealTimers();
	vi.restoreAllMocks();
});

async function setup(verifyDelivery?: boolean) {
	vi.useFakeTimers();
	const securityManager = await SecurityManager2.create();
	const securityClass = SecurityClass.S2_Authenticated;
	await securityManager.setKey(securityClass, new Bytes(16).fill(1));
	await securityManager.initializeSPAN(
		2,
		securityClass,
		new Bytes(16).fill(2),
		new Bytes(16).fill(3),
	);
	const peerSecurity = await SecurityManager2.create();
	await peerSecurity.setKey(securityClass, new Bytes(16).fill(1));
	const receiverEI = await peerSecurity.generateNonce(1);
	const context: CCEncodingContext = {
		ownNodeId: 1,
		homeId: 0x12345678,
		securityManager: undefined,
		securityManager2: securityManager,
		securityManagerLR: undefined,
		getDeviceConfig: () => undefined,
		getSupportedCCVersion: () => 1,
		getHighestSecurityClass: () => securityClass,
		hasSecurityClass: (_nodeId, sc) => sc === securityClass,
		setSecurityClass: () => {},
	};
	// Exercise the firmware API, generator and wait lifecycle without a controller or simulated device.
	const sendCommand = vi.fn(async () => undefined);
	const api = new FirmwareUpdateMetaDataCCAPI(
		{ sendCommand } as unknown as ConstructorParameters<
			typeof FirmwareUpdateMetaDataCCAPI
		>[0],
		{ nodeId: 2, index: 0 } as ConstructorParameters<
			typeof FirmwareUpdateMetaDataCCAPI
		>[1],
	);
	await api.sendFirmwareFragment(1, false, new Bytes(20).fill(7));
	const [fragment, options] = sendCommand.mock.calls[0] as unknown as [
		FirmwareUpdateMetaDataCCReport,
		{ s2VerifyDelivery?: boolean },
	];
	const host = {
		awaitedCommands: [] as {
			predicate: (cc: CommandClass) => boolean;
			handler: (cc: CommandClass) => void;
			consume?: boolean;
		}[],
		getSecurityManager2: () => securityManager,
		getHighestSecurityClass: () => securityClass,
		getNode: () => undefined,
		exceedsMaxPayloadLength: async () => false,
		waitForCommand: Driver.prototype.waitForCommand,
		controllerLog: { logNode: vi.fn() },
	};
	const driver = host as unknown as Driver;
	const msg = new SendDataBridgeRequest({
		sourceNodeId: 1,
		command: new Security2CCMessageEncapsulation({
			nodeId: 2,
			encapsulated: fragment,
			verifyDelivery: verifyDelivery ?? options.s2VerifyDelivery,
		}),
	});
	const generator = secureMessageGeneratorS2(driver, context, msg, () => {});
	const deliver = async (cc: CommandClass) => {
		const matches = host.awaitedCommands.filter((e) => e.predicate(cc));
		for (const e of matches) e.handler(cc);
		await Promise.resolve();
		await Promise.resolve();
		return matches;
	};
	const nonce = (nodeId = 2) =>
		new Security2CCNonceReport({
			nodeId,
			sequenceNumber: 10,
			SOS: true,
			MOS: false,
			receiverEI,
		});
	const ack = () =>
		new SendDataBridgeRequestTransmitReport({
			callbackId: 1,
			transmitStatus: TransmitStatus.OK,
		});
	const begin = async () => {
		const next = await generator.next();
		expect(next.done).toBe(false);
		msg.markAsSent();
		return msg.serializeCC(context);
	};
	const peerContext = {
		...context,
		ownNodeId: 2,
		sourceNodeId: 1,
		securityManager2: peerSecurity,
		frameType: "singlecast" as const,
	};
	return {
		peerContext,
		generator,
		msg,
		context,
		host,
		deliver,
		nonce,
		ack,
		begin,
		options,
	};
}

test.each(["before", "after"])(
	"firmware SOS %s the transmit callback triggers a new SPAN and one retransmission",
	async (timing) => {
		const s = await setup(true);
		const first = await s.begin();
		if (timing === "before") {
			await vi.advanceTimersByTimeAsync(12_000);
			await s.deliver(s.nonce());
		}
		const pending = s.generator.next(s.ack());
		if (timing === "after") {
			await vi.advanceTimersByTimeAsync(100);
			await s.deliver(s.nonce());
		}
		await vi.advanceTimersByTimeAsync(500);
		const retry = await pending;
		expect(retry.done).toBe(false);
		const second = await s.msg.serializeCC(s.context);
		expect(second.equals(first)).toBe(false);
		// The unencrypted S2 extension is a SPAN extension carrying fresh sender entropy.
		expect(second[3] & 1).toBe(1);
		expect(second[5] & 0x3f).toBe(1);
		// Firmware Report has no receive-side parser; inspect its authenticated plaintext at that boundary.
		const parseFragment = vi
			.spyOn(FirmwareUpdateMetaDataCCReport, "from")
			.mockImplementation((raw, ctx) => {
				expect(raw.payload.subarray(0, 22)).toEqual(
					Bytes.concat([new Bytes([0, 1]), new Bytes(20).fill(7)]),
				);
				return new FirmwareUpdateMetaDataCCReport({
					nodeId: ctx.sourceNodeId,
					reportNumber: 1,
					isLast: false,
					firmwareData: new Bytes(20).fill(7),
				});
			});
		const decoded = await CommandClass.parse(second, s.peerContext);
		expect(parseFragment).toHaveBeenCalledOnce();
		expect(decoded).toBeInstanceOf(Security2CCMessageEncapsulation);
		expect(
			(decoded as Security2CCMessageEncapsulation).encapsulated,
		).toMatchObject({
			reportNumber: 1,
			firmwareData: new Bytes(20).fill(7),
		});
		s.msg.markAsSent();
		const finished = s.generator.next(s.ack());
		await vi.advanceTimersByTimeAsync(500);
		expect((await finished).done).toBe(true);
		expect(s.host.awaitedCommands).toHaveLength(0);
	},
);

test.each(["before", "after"])(
	"a second SOS %s the callback stops recovery instead of endlessly retransmitting",
	async (timing) => {
		const s = await setup();
		await s.begin();
		await s.deliver(s.nonce());
		expect((await s.generator.next(s.ack())).done).toBe(false);
		await s.msg.serializeCC(s.context);
		s.msg.markAsSent();
		if (timing === "before") await s.deliver(s.nonce());
		const rejected = expect(
			s.generator.next(s.ack()),
		).rejects.toMatchObject({
			code: ZWaveErrorCodes.Security2CC_CannotDecode,
		});
		if (timing === "after") {
			await vi.advanceTimersByTimeAsync(100);
			await s.deliver(s.nonce());
		}
		await rejected;
		expect(s.host.awaitedCommands).toHaveLength(0);
	},
);

test("successful delivery waits only the post-transmission grace period and ignores another node", async () => {
	const s = await setup();
	await s.begin();
	await vi.advanceTimersByTimeAsync(20_000);
	expect(await s.deliver(s.nonce(3))).toHaveLength(0);
	let done = false;
	const pending = s.generator.next(s.ack()).then((result) => {
		done = true;
		return result;
	});
	await vi.advanceTimersByTimeAsync(499);
	expect(done).toBe(false);
	await vi.advanceTimersByTimeAsync(1);
	expect((await pending).done).toBe(true);
	expect(s.host.awaitedCommands).toHaveLength(0);
});

test("transmission failure cleans up the nonce wait", async () => {
	const s = await setup();
	await s.begin();
	const error = new Error("Serial API failed");
	await expect(s.generator.throw(error)).rejects.toBe(error);
	expect(s.host.awaitedCommands).toHaveLength(0);
});

test("explicit delivery-verification opt-out retains its timing", async () => {
	const s = await setup(false);
	await s.begin();
	expect(s.host.awaitedCommands).toHaveLength(0);
	expect((await s.generator.next(s.ack())).done).toBe(true);
});

test("firmware fragment API enables S2 delivery verification", async () => {
	const s = await setup();
	expect(s.options.s2VerifyDelivery).toBe(true);
});

test("closing the generator removes the pending nonce observer", async () => {
	const s = await setup();
	await s.begin();
	expect(s.host.awaitedCommands).toHaveLength(1);
	await s.generator.return(s.ack());
	expect(s.host.awaitedCommands).toHaveLength(0);
});
