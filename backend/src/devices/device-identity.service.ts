import { Injectable } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'node:crypto';

type VerificationResult = {
  valid: boolean;
  reason?: string;
};

@Injectable()
export class DeviceIdentityService {
  private readonly secret =
    process.env.DEVICE_HMAC_SECRET ?? 'dev-only-change-me';
  private readonly maxSkewMs = Number(
    process.env.DEVICE_HMAC_MAX_SKEW_MS ?? 5 * 60 * 1000,
  );

  verify(
    deviceId: string,
    timestamp: string,
    signatureHex: string,
  ): VerificationResult {
    const tsMs = Date.parse(timestamp);
    if (!Number.isFinite(tsMs)) {
      return { valid: false, reason: 'invalid timestamp format' };
    }

    if (Math.abs(Date.now() - tsMs) > this.maxSkewMs) {
      return { valid: false, reason: 'timestamp outside allowed skew window' };
    }

    const canonical = `${deviceId}.${timestamp}`;
    const expected = createHmac('sha256', this.secret)
      .update(canonical)
      .digest();

    let provided: Buffer;
    try {
      provided = Buffer.from(signatureHex, 'hex');
    } catch {
      return { valid: false, reason: 'invalid signature encoding' };
    }

    if (provided.length !== expected.length) {
      return { valid: false, reason: 'signature length mismatch' };
    }

    if (!timingSafeEqual(expected, provided)) {
      return { valid: false, reason: 'signature mismatch' };
    }

    return { valid: true };
  }
}
