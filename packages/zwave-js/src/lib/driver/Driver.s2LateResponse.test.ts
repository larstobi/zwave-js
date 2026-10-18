import {
	BasicCCSet,
	type CCEncodingContext,
	type CommandClass,
	ManufacturerSpecificCCGet,
	ManufacturerSpecificCCReport,
	Security2CCMessageEncapsulation,
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
import { afterEach, expect, test, vi } from "vitest";

import { Driver } from "./Driver.js";
import { createMessageGenerator } from "./MessageGenerators.js";
import { Transaction } from "./Transaction.js";

afterEach(() => vi.useRealTimers());

async function setup(
	options: {
		command?: CommandClass;
		secure?: boolean;
		failure?: ZWaveError;
		reportTimeout?: number;
		finalStatus?: TransmitStatus;
	} = {},
) {
	vi.useFakeTimers();
	const manager = await SecurityManager2.create();
	const securityClass = SecurityClass.S2_Authenticated;
	await manager.setKey(securityClass, new Bytes(16).fill(1));
	await manager.initializeSPAN(
		2,
		securityClass,
		new Bytes(16).fill(2),
		new Bytes(16).fill(3),
	);
	const context: CCEncodingContext = {
		ownNodeId: 1,
		homeId: 0x12345678,
		securityManager: undefined,
		securityManager2: manager,
		securityManagerLR: undefined,
		getDeviceConfig: () => undefined,
		getSupportedCCVersion: () => 1,
		getHighestSecurityClass: () => securityClass,
		hasSecurityClass: (_id, sc) => sc === securityClass,
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
		new Security2CCMessageEncapsulation({
			nodeId: 2,
			encapsulated: new ManufacturerSpecificCCReport({
				nodeId: 2,
				manufacturerId: 411,
				productType: 4,
				productId: 516,
			}),
		}),
	);
	const nonce = (nodeId = 2, SOS = true) =>
		received(
			new Security2CCNonceReport({
				nodeId,
				sequenceNumber: 53,
				SOS,
				MOS: !SOS,
				receiverEI: SOS ? new Bytes(16).fill(4) : undefined,
			}),
		);
	const sent: string[] = [];
	const failures: SendDataBridgeRequestTransmitReport[] = [];
	const host = {
		awaitedCommands: [],
		waitForCommand: Driver.prototype.waitForCommand,
		awaitedMessages: [] as {
			predicate: (m: Message) => boolean;
			handler: (m: Message) => void;
		}[],
		_options: { attempts: { sendData: 3 } },
		options: { attempts: { sendDataJammed: 3 } },
		controller: { status: ControllerStatus.Ready },
		controllerLog: { logNode: vi.fn() },
		getSecurityManager2: () => manager,
		getHighestSecurityClass: () => securityClass,
		getNode: () => undefined,
		exceedsMaxPayloadLength: async () => false,
		unwrapCommands: () => {},
		getReportTimeout: () => options.reportTimeout ?? 1000,
		waitForMessage: Driver.prototype.waitForMessage,
		mayRetrySerialAPICommand: Driver.prototype["mayRetrySerialAPICommand"],
		queueSerialAPICommand: async (message: Message) => {
			const msg = message as SendDataBridgeRequest;
			sent.push((await msg.serializeCC(context)).toString("hex"));
			msg.markAsSent();
			if (options.failure) throw options.failure;
			if (sent.length <= 3) {
				await new Promise((resolve) => setTimeout(resolve, 20_000));
				const fail =
					sent.length < 3
					|| options.finalStatus === TransmitStatus.Fail
						? SendDataBridgeRequestTransmitReport.from(
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
							)
						: new SendDataBridgeRequestTransmitReport({
								callbackId: 100,
								transmitStatus: TransmitStatus.NoAck,
							});
				failures.push(fail);
				return fail;
			}
			msg.prematureNodeUpdate = report;
			return new SendDataBridgeRequestTransmitReport({
				callbackId: 101,
				transmitStatus: TransmitStatus.OK,
			});
		},
	};
	const driver = host as unknown as Driver;
	const inner =
		options.command ?? new ManufacturerSpecificCCGet({ nodeId: 2 });
	const msg = new SendDataBridgeRequest({
		sourceNodeId: 1,
		maxSendAttempts: 3,
		command:
			options.secure === false
				? inner
				: new Security2CCMessageEncapsulation({
						nodeId: 2,
						encapsulated: inner,
					}),
	});
	const onSettled = vi.fn();
	const transaction = new Transaction(driver, {
		message: msg,
		priority: MessagePriority.Normal,
		parts: createMessageGenerator(driver, context, msg, () => {}),
		onSettled,
	});
	// Exercise the real executor, generator, response matching and waiter lifecycle with Serial API results.
	let error: unknown;
	let done = false;
	const execution = Driver.prototype["executeTransaction"]
		.call(driver, transaction)
		.catch((e) => {
			error = e;
		})
		.finally(() => {
			done = true;
		});
	const deliver = async (message: Message) => {
		const matches = host.awaitedMessages.filter((e) =>
			e.predicate(message),
		);
		for (const entry of matches) entry.handler(message);
		await Promise.resolve();
		await Promise.resolve();
		return matches.length;
	};
	const exhaust = async () => {
		await vi.advanceTimersByTimeAsync(60_000);
	};
	return {
		sent,
		failures,
		host,
		report,
		nonce,
		execution,
		deliver,
		exhaust,
		onSettled,
		get error() {
			return error;
		},
		get done() {
			return done;
		},
	};
}

test.each([TransmitStatus.NoAck, TransmitStatus.Fail])(
	"an SOS arriving after the final failed callback (%s) recovers the S2 query",
	async (finalStatus) => {
		const s = await setup({ finalStatus });
		await s.exhaust();
		expect(s.sent).toHaveLength(3);
		expect(s.done).toBe(false);
		await vi.advanceTimersByTimeAsync(1119);
		expect(await s.deliver(s.nonce())).toBe(1);
		await vi.advanceTimersByTimeAsync(0);
		await s.execution;
		expect(s.error).toBeUndefined();
		expect(s.sent).toHaveLength(4);
		expect(s.sent[1]).toBe(s.sent[0]);
		expect(s.sent[2]).toBe(s.sent[0]);
		expect(s.sent[3]).not.toBe(s.sent[0]);
		const retry = Bytes.from(s.sent[3], "hex");
		expect(retry[3] & 1).toBe(1);
		expect(retry[5] & 0x3f).toBe(1);
		expect(s.onSettled).toHaveBeenCalledExactlyOnceWith({
			status: "fulfilled",
			value: s.report,
		});
		expect(s.host.awaitedMessages).toHaveLength(0);
	},
);

test("a late matching report completes the query without another transmission", async () => {
	const s = await setup();
	await s.exhaust();
	await vi.advanceTimersByTimeAsync(1119);
	expect(await s.deliver(s.report)).toBe(1);
	await s.execution;
	expect(s.error).toBeUndefined();
	expect(s.sent).toHaveLength(3);
	expect(s.onSettled).toHaveBeenCalledExactlyOnceWith({
		status: "fulfilled",
		value: s.report,
	});
	expect(s.host.awaitedMessages).toHaveLength(0);
});

test.each([500, 1000])(
	"silence retains the original failure after RTT plus configured %s ms report timeout",
	async (reportTimeout) => {
		const s = await setup({ reportTimeout });
		await s.exhaust();
		expect(await s.deliver(s.nonce(3))).toBe(0);
		expect(await s.deliver(s.nonce(2, false))).toBe(0);
		await vi.advanceTimersByTimeAsync(20_000 + reportTimeout - 1);
		expect(s.done).toBe(false);
		await vi.advanceTimersByTimeAsync(1);
		await s.execution;
		expect(s.error).toMatchObject({
			code: ZWaveErrorCodes.Controller_CallbackNOK,
			context: s.failures[2],
		});
		expect(s.sent).toHaveLength(3);
		expect(s.host.awaitedMessages).toHaveLength(0);
	},
);

test.each(["unsecured query", "S2 SET"])(
	"%s does not gain a late-response wait",
	async (kind) => {
		const s = await setup(
			kind === "S2 SET"
				? { command: new BasicCCSet({ nodeId: 2, targetValue: 1 }) }
				: { secure: false },
		);
		await s.exhaust();
		await s.execution;
		expect(s.error).toMatchObject({
			code: ZWaveErrorCodes.Controller_CallbackNOK,
		});
		expect(s.host.awaitedMessages).toHaveLength(0);
		expect(s.sent).toHaveLength(3);
	},
);

test("a missing controller callback still fails immediately", async () => {
	const failure = new ZWaveError(
		"Missing callback",
		ZWaveErrorCodes.Controller_Timeout,
		"callback",
	);
	const s = await setup({ failure });
	await vi.advanceTimersByTimeAsync(0);
	await s.execution;
	expect(s.error).toBe(failure);
	expect(s.sent).toHaveLength(1);
	expect(s.host.awaitedMessages).toHaveLength(0);
});
