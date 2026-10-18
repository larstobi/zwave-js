import {
	EncapsulationFlags,
	MessagePriority,
	SupervisionStatus,
	TransmitOptions,
	ZWaveError,
	ZWaveErrorCodes,
} from "@zwave-js/core";
import { expect, test, vi } from "vitest";

import type { CCAPIHost } from "../lib/API.js";

import { SupervisionCCAPI, SupervisionCCReport } from "./SupervisionCC.js";

function createAPI(sendCommand: CCAPIHost["sendCommand"]) {
	return new SupervisionCCAPI({ sendCommand } as CCAPIHost, {
		nodeId: 128,
		index: 0,
		virtual: false,
		supportsCC: () => true,
		controlsCC: () => false,
	});
}

test.each([false, true])(
	"a failed Supervision reply must not change node status (lowPriority=%s)",
	async (lowPriority) => {
		const sendCommand = vi
			.fn<CCAPIHost["sendCommand"]>()
			.mockRejectedValue(
				new ZWaveError(
					"Transmission failed",
					ZWaveErrorCodes.Controller_CallbackNOK,
				),
			);
		const api = createAPI(sendCommand);

		await expect(
			api.sendReport({
				sessionId: 3,
				moreUpdatesFollow: false,
				status: SupervisionStatus.Success,
				encapsulationFlags: EncapsulationFlags.Security,
				lowPriority,
			}),
		).resolves.toBeUndefined();

		expect(sendCommand).toHaveBeenCalledTimes(1);
		const [report, options] = sendCommand.mock.calls[0];
		expect(report).toBeInstanceOf(SupervisionCCReport);
		expect(report.encapsulationFlags).toBe(EncapsulationFlags.Security);
		// Failed best-effort replies must not invalidate concurrent transactions
		// such as the identity queries preceding an OTA firmware transfer.
		expect(options).toMatchObject({
			changeNodeStatusOnMissingACK: false,
			maxSendAttempts: 1,
			transmitOptions: TransmitOptions.DEFAULT_NOACK,
			s2VerifyDelivery: false,
			priority: lowPriority
				? MessagePriority.ImmediateLow
				: MessagePriority.Immediate,
		});
	},
);

test("Supervision replies still propagate non-transmission errors", async () => {
	const error = new ZWaveError(
		"Invalid argument",
		ZWaveErrorCodes.Argument_Invalid,
	);
	const sendCommand = vi
		.fn<CCAPIHost["sendCommand"]>()
		.mockRejectedValue(error);

	await expect(
		createAPI(sendCommand).sendReport({
			sessionId: 3,
			moreUpdatesFollow: false,
			status: SupervisionStatus.Success,
		}),
	).rejects.toBe(error);
});
