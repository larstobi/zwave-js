import {
	BasicCCSet,
	TransportServiceCCSegmentComplete,
	TransportServiceCCSegmentRequest,
	TransportServiceCCSegmentWait,
} from "@zwave-js/cc";
import { SecurityClass } from "@zwave-js/core";
import { expect, test, vi } from "vitest";

import { Driver } from "./Driver.js";

test.each([
	SecurityClass.S0_Legacy,
	SecurityClass.S2_Unauthenticated,
	SecurityClass.S2_Authenticated,
	SecurityClass.S2_AccessControl,
])(
	"transport controls remain usable with security class %s",
	(securityClass) => {
		const host = {
			_controller: {
				nodes: new Map([
					[
						128,
						{
							getHighestSecurityClass: () => securityClass,
							isCCSecure: () => true,
						},
					],
				]),
			},
			controllerLog: { logNode: vi.fn() },
		};
		const check = (cc: Parameters<Driver["isSecurityLevelTooLow"]>[0]) =>
			Driver.prototype["isSecurityLevelTooLow"].call(
				host as unknown as Driver,
				cc,
			);
		for (const cc of [
			new TransportServiceCCSegmentRequest({
				nodeId: 128,
				sessionId: 1,
				datagramOffset: 39,
			}),
			new TransportServiceCCSegmentComplete({
				nodeId: 128,
				sessionId: 1,
			}),
			new TransportServiceCCSegmentWait({
				nodeId: 128,
				pendingSegments: 0,
			}),
		]) {
			expect(check(cc)).toBe(false);
		}
		// Reassembled application data still goes through the normal security check.
		expect(check(new BasicCCSet({ nodeId: 128, targetValue: 1 }))).toBe(
			true,
		);
		// Transport controls from nodes outside the network are not accepted.
		expect(
			check(
				new TransportServiceCCSegmentComplete({
					nodeId: 129,
					sessionId: 1,
				}),
			),
		).toBe(true);
	},
);
