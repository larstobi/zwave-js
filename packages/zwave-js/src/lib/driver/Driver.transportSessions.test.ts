import {
	BasicCCReport,
	TransportServiceCCFirstSegment,
	TransportServiceCCSegmentComplete,
	TransportServiceCCSubsequentSegment,
	TransportServiceTimeouts,
} from "@zwave-js/cc";
import { Bytes } from "@zwave-js/shared";
import { afterEach, expect, test, vi } from "vitest";

import { Driver } from "./Driver.js";

afterEach(() => {
	vi.clearAllTimers();
	vi.useRealTimers();
});

function setup() {
	vi.useFakeTimers();
	const sessions = { transportService: new Map() };
	const host = {
		ensureNodeSessions: () => sessions,
		controllerLog: { logNode: vi.fn() },
		driverLog: { print: vi.fn() },
		sendCommand: vi.fn(async (_command: unknown) => {}),
		getCCParsingContext: () => ({
			getSupportedCCVersion: () => 1,
		}),
	};
	const receive = (
		command:
			| TransportServiceCCFirstSegment
			| TransportServiceCCSubsequentSegment,
	) =>
		Driver.prototype["handleTransportServiceCommand"].call(
			host as unknown as Driver,
			command,
		);
	const first = (sessionId: number) =>
		receive(
			new TransportServiceCCFirstSegment({
				nodeId: 211,
				sessionId,
				datagramSize: 3,
				partialDatagram: Bytes.from([0x20, 0x03]),
			}),
		);
	const last = (sessionId: number) =>
		receive(
			new TransportServiceCCSubsequentSegment({
				nodeId: 211,
				sessionId,
				datagramSize: 3,
				datagramOffset: 2,
				partialDatagram: Bytes.from([42]),
			}),
		);
	return { sessions, host, first, last };
}

const timeout = TransportServiceTimeouts.requestMissingSegmentR2;

test.each([6, 15])(
	"replacing an RX session with session %s cancels its missing-segment timer",
	async (replacementId) => {
		const s = setup();
		await s.first(15);
		await vi.advanceTimersByTimeAsync(timeout / 2);
		await s.first(replacementId);
		await vi.advanceTimersByTimeAsync(timeout / 2);
		expect(s.host.sendCommand).not.toHaveBeenCalled();
		await vi.advanceTimersByTimeAsync(timeout / 2);
		expect(s.host.sendCommand).toHaveBeenCalledExactlyOnceWith(
			expect.objectContaining({
				sessionId: replacementId,
				datagramOffset: 2,
			}),
			expect.anything(),
		);
	},
);

test("a superseded session's pending request cannot restart its timer or delete the replacement", async () => {
	const s = setup();
	let finishRequest!: () => void;
	s.host.sendCommand.mockImplementationOnce(
		() =>
			new Promise<void>((resolve) => {
				finishRequest = resolve;
			}),
	);
	await s.first(15);
	await vi.advanceTimersByTimeAsync(timeout);
	expect(s.host.sendCommand).toHaveBeenCalledTimes(1);
	await s.first(15);
	const replacement = s.sessions.transportService.get(15);
	finishRequest();
	await vi.advanceTimersByTimeAsync(timeout);
	expect(s.sessions.transportService.get(15)).toBe(replacement);
	expect(s.host.controllerLog.logNode).not.toHaveBeenCalledWith(
		211,
		expect.objectContaining({ level: "error" }),
	);
	expect(await s.last(15)).toBeInstanceOf(BasicCCReport);
	expect(vi.getTimerCount()).toBe(0);
});

test("a missing-segment request completed after the datagram cannot rearm a completed session", async () => {
	const s = setup();
	let finishRequest!: () => void;
	s.host.sendCommand.mockImplementationOnce(
		() =>
			new Promise<void>((resolve) => {
				finishRequest = resolve;
			}),
	);
	await s.first(15);
	await vi.advanceTimersByTimeAsync(timeout);
	expect(await s.last(15)).toBeInstanceOf(BasicCCReport);
	finishRequest();
	await vi.advanceTimersByTimeAsync(timeout * 2);
	expect(
		s.host.sendCommand.mock.calls.filter(
			([cc]) => cc instanceof TransportServiceCCSegmentComplete,
		),
	).toHaveLength(1);
	expect(vi.getTimerCount()).toBe(0);
	// A real retransmission must still receive its acknowledgment.
	expect(await s.last(15)).toBeUndefined();
	expect(
		s.host.sendCommand.mock.calls.filter(
			([cc]) => cc instanceof TransportServiceCCSegmentComplete,
		),
	).toHaveLength(2);
});
