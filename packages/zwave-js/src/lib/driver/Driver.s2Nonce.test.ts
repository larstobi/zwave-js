import {
	type CCEncodingContext,
	type CommandClass,
	ManufacturerSpecificCCGet,
	ManufacturerSpecificCCReport,
	Security2CCMessageEncapsulation,
	Security2CCNonceGet,
	Security2CCNonceReport,
} from "@zwave-js/cc";
import {
	ControllerStatus,
	MessagePriority,
	NodeIDType,
	SecurityClass,
	SecurityManager2,
	TransmitStatus,
	ZWaveError,
	ZWaveErrorCodes,
} from "@zwave-js/core";
import { type Message, MessageRaw } from "@zwave-js/serial";
import {
	BridgeApplicationCommandRequest,
	SendDataBridgeRequest,
	SendDataBridgeRequestTransmitReport,
} from "@zwave-js/serial/serialapi";
import { Bytes } from "@zwave-js/shared";
import { expect, test, vi } from "vitest";

import { Driver } from "./Driver.js";
import { createMessageGenerator } from "./MessageGenerators.js";
import { Transaction } from "./Transaction.js";

async function setup(
	statuses: (TransmitStatus | ZWaveError)[],
	maxSendAttempts = 3,
	receiveNonceReport = true,
) {
	const securityManager = await SecurityManager2.create();
	const securityClass = SecurityClass.S2_Authenticated;
	await securityManager.setKey(securityClass, new Bytes(16).fill(1));
	const receiverEI = new Bytes(16).fill(2);
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
	const received = (command: CommandClass) =>
		new BridgeApplicationCommandRequest({
			command,
			ownNodeId: 1,
			targetNodeId: 1,
			frameType: "singlecast",
			routedBusy: false,
			isExploreFrame: false,
			isForeignFrame: false,
			fromForeignHomeId: false,
		});
	const report = received(
		new ManufacturerSpecificCCReport({
			nodeId: 2,
			manufacturerId: 0x019b,
			productType: 4,
			productId: 0x0204,
		}),
	);
	const sent: { command: CommandClass; payload: string }[] = [];
	let nonceAttempts = 0;
	const onSettled = vi.fn();
	// Exercise the transaction and generator with Serial API results only.
	const host = {
		ownNodeId: 1,
		_options: { attempts: { sendData: 3 } },
		options: { attempts: { sendDataJammed: 3 } },
		controller: {
			status: ControllerStatus.Ready,
			isFunctionSupported: () => true,
		},
		getSecurityManager2: () => securityManager,
		getNode: () => undefined,
		getHighestSecurityClass: () => securityClass,
		encapsulateCommands: (command: CommandClass) => command,
		createSendDataMessage: Driver.prototype.createSendDataMessage,
		mayRetrySerialAPICommand: Driver.prototype["mayRetrySerialAPICommand"],
		exceedsMaxPayloadLength: async () => false,
		unwrapCommands: () => {},
		getReportTimeout: () => 1000,
		waitForMessage: vi.fn(async () => {
			throw new ZWaveError(
				"No response",
				ZWaveErrorCodes.Controller_NodeTimeout,
			);
		}),
		queueSerialAPICommand: async (message: Message) => {
			const msg = message as SendDataBridgeRequest;
			sent.push({
				command: msg.command!,
				payload: (await msg.serializeCC(context)).toString("hex"),
			});
			msg.markAsSent();
			let status = TransmitStatus.OK;
			if (msg.command instanceof Security2CCNonceGet) {
				const result = statuses[nonceAttempts++] ?? TransmitStatus.OK;
				if (result instanceof Error) throw result;
				status = result;
				if (status === TransmitStatus.OK && receiveNonceReport) {
					securityManager.storeRemoteEI(2, receiverEI);
					msg.prematureNodeUpdate = received(
						new Security2CCNonceReport({
							nodeId: 2,
							sequenceNumber: 173,
							SOS: true,
							MOS: false,
							receiverEI,
						}),
					);
				}
			} else {
				msg.prematureNodeUpdate = report;
			}
			if (status === TransmitStatus.Fail) {
				// Captured after a 20.62-second nonce transmission and SendDataAbort.
				return SendDataBridgeRequestTransmitReport.from(
					MessageRaw.parse(
						Bytes.from(
							"011d00a99502080e017f7f7f7f7f000105d1000000020e00007f7f7f7f7f02",
							"hex",
						),
					),
					{
						...context,
						nodeIdType: NodeIDType.Long,
						sdkVersion: "7.24.2",
						requestStorage: undefined,
					},
				);
			}
			return new SendDataBridgeRequestTransmitReport({
				callbackId: 149,
				transmitStatus: status,
			});
		},
	};
	const driver = host as unknown as Driver;
	const msg = new SendDataBridgeRequest({
		sourceNodeId: 1,
		maxSendAttempts,
		command: new Security2CCMessageEncapsulation({
			nodeId: 2,
			encapsulated: new ManufacturerSpecificCCGet({ nodeId: 2 }),
		}),
	});
	const transaction = new Transaction(driver, {
		message: msg,
		priority: MessagePriority.Normal,
		parts: createMessageGenerator(driver, context, msg, () => {}),
		onSettled,
	});
	const execute = async () => {
		await Driver.prototype["executeTransaction"].call(driver, transaction);
		const result = onSettled.mock.calls[0]?.[0];
		if (result?.status === "rejected") throw result.reason;
	};

	return { execute, sent, onSettled, report };
}

test.each([TransmitStatus.Fail, TransmitStatus.NoAck])(
	"an S2 nonce transmission failure (%s) can recover within the command's retry budget",
	async (status) => {
		const s = await setup([status, TransmitStatus.OK]);
		await s.execute();
		expect(s.sent.map((msg) => msg.command.constructor)).toEqual([
			Security2CCNonceGet,
			Security2CCNonceGet,
			Security2CCMessageEncapsulation,
		]);
		expect(s.sent[1].payload).toBe(s.sent[0].payload);
		expect(s.onSettled).toHaveBeenCalledExactlyOnceWith({
			status: "fulfilled",
			value: s.report,
		});
	},
);

test.each([1, 2, 3])(
	"S2 nonce retries stop at the caller's limit of %s attempts",
	async (attempts) => {
		const s = await setup(
			Array(attempts).fill(TransmitStatus.Fail),
			attempts,
		);
		await expect(s.execute()).rejects.toMatchObject({
			code: ZWaveErrorCodes.Controller_CallbackNOK,
		});
		expect(s.sent).toHaveLength(attempts);
		expect(
			s.sent.every((msg) => msg.command instanceof Security2CCNonceGet),
		).toBe(true);
		expect(s.onSettled).not.toHaveBeenCalled();
	},
);

test("a successful S2 nonce exchange does not use extra attempts", async () => {
	const s = await setup([TransmitStatus.OK]);
	await s.execute();
	expect(s.sent.map((msg) => msg.command.constructor)).toEqual([
		Security2CCNonceGet,
		Security2CCMessageEncapsulation,
	]);
	expect(s.onSettled).toHaveBeenCalledExactlyOnceWith({
		status: "fulfilled",
		value: s.report,
	});
});

test("an acknowledged nonce request without a Nonce Report is not retransmitted", async () => {
	const s = await setup([TransmitStatus.OK], 3, false);
	await expect(s.execute()).rejects.toMatchObject({
		code: ZWaveErrorCodes.Controller_NodeTimeout,
	});
	expect(s.sent).toHaveLength(1);
	expect(s.sent[0].command).toBeInstanceOf(Security2CCNonceGet);
});

test("a missing controller callback still stops the nonce exchange immediately", async () => {
	const error = new ZWaveError(
		"No callback",
		ZWaveErrorCodes.Controller_Timeout,
		"callback",
	);
	const s = await setup([error]);
	await expect(s.execute()).rejects.toBe(error);
	expect(s.sent).toHaveLength(1);
	expect(s.sent[0].command).toBeInstanceOf(Security2CCNonceGet);
});
