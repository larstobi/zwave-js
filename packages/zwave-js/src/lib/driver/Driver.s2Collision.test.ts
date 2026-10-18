import {
	BasicCCReport,
	type CCEncodingContext,
	type CCParsingContext,
	CommandClass,
	InvalidCC,
	Security2CCMessageEncapsulation,
	VersionCCGet,
} from "@zwave-js/cc";
import {
	SecurityClass,
	SecurityManager2,
	TransmitStatus,
	ZWaveError,
	ZWaveErrorCodes,
} from "@zwave-js/core";
import {
	SendDataBridgeRequest,
	SendDataBridgeRequestTransmitReport,
} from "@zwave-js/serial/serialapi";
import { AsyncQueue, Bytes } from "@zwave-js/shared";
import { afterEach, expect, test, vi } from "vitest";

import { Driver } from "./Driver.js";
import type { SerialAPIQueueItem } from "./Queue.js";

afterEach(() => {
	vi.useRealTimers();
});

async function setup() {
	vi.useFakeTimers();

	const controllerSecurity = await SecurityManager2.create();
	const peerSecurity = await SecurityManager2.create();
	const securityClass = SecurityClass.S2_Authenticated;
	const key = new Bytes(16).fill(1);
	const senderEI = new Bytes(16).fill(2);
	const receiverEI = new Bytes(16).fill(3);
	for (const [manager, peerId] of [
		[controllerSecurity, 2],
		[peerSecurity, 1],
	] as const) {
		await manager.setKey(securityClass, key);
		await manager.initializeSPAN(
			peerId,
			securityClass,
			senderEI,
			receiverEI,
		);
	}
	controllerSecurity.storeSequenceNumber(2, 216);

	const context: CCEncodingContext = {
		ownNodeId: 1,
		homeId: 0x12345678,
		securityManager: undefined,
		securityManager2: controllerSecurity,
		securityManagerLR: undefined,
		getDeviceConfig: () => undefined,
		getSupportedCCVersion: () => 1,
		getHighestSecurityClass: () => securityClass,
		hasSecurityClass: (_nodeId, sc) => sc === securityClass,
		setSecurityClass: () => {},
	};
	const parsingContext: CCParsingContext = {
		...context,
		sourceNodeId: 2,
		frameType: "singlecast",
	};
	const peerContext: CCEncodingContext = {
		...context,
		ownNodeId: 2,
		securityManager2: peerSecurity,
	};
	const request = new SendDataBridgeRequest({
		sourceNodeId: 1,
		command: new Security2CCMessageEncapsulation({
			nodeId: 2,
			sequenceNumber: 112,
			encapsulated: new VersionCCGet({ nodeId: 2 }),
		}),
	});
	// Payload sizing serializes the command before it enters the Serial API queue.
	const serializedRequest = await request.serializeCC(context);
	const report = (sequenceNumber = 217) =>
		new Security2CCMessageEncapsulation({
			nodeId: 1,
			sequenceNumber,
			encapsulated: new BasicCCReport({ nodeId: 1, currentValue: 42 }),
		}).serialize(peerContext);

	// Exercise the queue and codecs without a controller or simulated device.
	const serialAPIQueue = new AsyncQueue<SerialAPIQueueItem>();
	const host = { serialAPIQueue, getEncodingContext: () => context };
	const queueRequest = () =>
		Driver.prototype["queueSerialAPICommand"].call(
			host as unknown as Driver,
			request,
		);
	const nextQueued = async () =>
		(await serialAPIQueue[Symbol.asyncIterator]().next()).value!;
	const txReport = (transmitStatus: TransmitStatus) =>
		new SendDataBridgeRequestTransmitReport({
			callbackId: 1,
			transmitStatus,
		});

	return {
		context,
		parsingContext,
		request,
		serializedRequest,
		report,
		serialAPIQueue,
		queueRequest,
		nextQueued,
		txReport,
	};
}

test("a delayed S2 collision can be decoded while a cached SendData request is being retried", async () => {
	const s = await setup();
	let sending = s.queueRequest();
	let queued = await s.nextQueued();
	vi.advanceTimersByTime(20600);
	queued.result.resolve(s.txReport(TransmitStatus.Fail));
	await sending;

	sending = s.queueRequest();
	queued = await s.nextQueued();
	vi.advanceTimersByTime(16600);
	const incoming = await s.report();
	const received = await CommandClass.parse(incoming, s.parsingContext);
	queued.result.resolve(s.txReport(TransmitStatus.OK));
	await sending;

	expect(received).toBeInstanceOf(Security2CCMessageEncapsulation);
	expect(
		(received as Security2CCMessageEncapsulation).encapsulated,
	).toMatchObject({
		currentValue: 42,
	});
	expect(await s.request.serializeCC(s.context)).toEqual(s.serializedRequest);

	const duplicate = await CommandClass.parse(incoming, s.parsingContext);
	expect(duplicate).toBeInstanceOf(InvalidCC);
	expect((duplicate as InvalidCC).reason).toContain("Duplicate command");
	const nextReport = await CommandClass.parse(
		await s.report(218),
		s.parsingContext,
	);
	expect(nextReport).toBeInstanceOf(Security2CCMessageEncapsulation);
});

test.each([TransmitStatus.OK, TransmitStatus.Fail])(
	"the collision nonce expires again after a SendData result (%s)",
	async (status) => {
		const s = await setup();
		const sending = s.queueRequest();
		const queued = await s.nextQueued();
		vi.advanceTimersByTime(20000);
		queued.result.resolve(s.txReport(status));
		await sending;
		vi.advanceTimersByTime(501);

		const received = await CommandClass.parse(
			await s.report(),
			s.parsingContext,
		);
		expect(received).toBeInstanceOf(InvalidCC);
		expect((received as InvalidCC).reason).toBe(
			ZWaveErrorCodes.Security2CC_CannotDecode,
		);
	},
);

test("collision recovery still works during the grace period after transmission", async () => {
	const s = await setup();
	const sending = s.queueRequest();
	const queued = await s.nextQueued();
	vi.advanceTimersByTime(20000);
	queued.result.resolve(s.txReport(TransmitStatus.OK));
	await sending;
	vi.advanceTimersByTime(499);

	expect(
		await CommandClass.parse(await s.report(), s.parsingContext),
	).toBeInstanceOf(Security2CCMessageEncapsulation);
});

test.each(["reject", "abort"] as const)(
	"a rejected or discarded queued command releases its SPAN (%s)",
	async (action) => {
		const s = await setup();
		const sending = s.queueRequest();
		const rejected = expect(sending).rejects.toBeInstanceOf(ZWaveError);
		vi.advanceTimersByTime(20000);
		if (action === "reject") {
			const queued = await s.nextQueued();
			queued.result.reject(
				new ZWaveError("Timeout", ZWaveErrorCodes.Controller_Timeout),
			);
		} else {
			s.serialAPIQueue.abort();
		}
		await rejected;
		vi.advanceTimersByTime(501);

		const received = await CommandClass.parse(
			await s.report(),
			s.parsingContext,
		);
		expect(received).toBeInstanceOf(InvalidCC);
		expect((received as InvalidCC).reason).toBe(
			ZWaveErrorCodes.Security2CC_CannotDecode,
		);
	},
);

test("a retained SPAN cannot decode a collision with an unexpected sequence number", async () => {
	const s = await setup();
	const sending = s.queueRequest();
	const queued = await s.nextQueued();
	vi.advanceTimersByTime(37000);
	const received = await CommandClass.parse(
		await s.report(218),
		s.parsingContext,
	);
	queued.result.resolve(s.txReport(TransmitStatus.OK));
	await sending;

	expect(received).toBeInstanceOf(InvalidCC);
	expect((received as InvalidCC).reason).toBe(
		ZWaveErrorCodes.Security2CC_CannotDecode,
	);
});
