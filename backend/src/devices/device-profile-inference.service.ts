import { Injectable } from '@nestjs/common';

type InferenceInput = {
  macAddress?: string | null;
  fingerprint?: string | null;
  hostname?: string | null;
  vendor?: string | null;
  model?: string | null;
};

type InferenceResult = {
  vendor?: string;
  model?: string;
};

const OUI_VENDOR_MAP: Record<string, string> = {
  'B8:27:EB': 'Raspberry Pi',
  'DC:A6:32': 'Raspberry Pi',
  'E4:5F:01': 'Raspberry Pi',
  '84:F3:EB': 'Apple',
  '3C:5A:B4': 'Google Nest',
  'EC:FA:BC': 'Google Nest',
  '48:3F:DA': 'Amazon',
  'D8:3A:DD': 'Espressif',
  '24:6F:28': 'Espressif',
  '34:AB:37': 'Shelly',
};

const FINGERPRINT_RULES: Array<{
  pattern: RegExp;
  vendor?: string;
  model?: string;
}> = [
  {
    pattern: /raspberry[\s_-]*pi/i,
    vendor: 'Raspberry Pi',
    model: 'Raspberry Pi',
  },
  { pattern: /google[\s_-]*nest|nest[-_\s]*cam/i, vendor: 'Google Nest' },
  { pattern: /shelly/i, vendor: 'Shelly' },
  { pattern: /esp32|espressif/i, vendor: 'Espressif', model: 'ESP32' },
  { pattern: /nrf52|nordic/i, vendor: 'Nordic Semiconductor' },
];

@Injectable()
export class DeviceProfileInferenceService {
  infer(input: InferenceInput): InferenceResult {
    const result: InferenceResult = {};
    const normalizedFingerprint = this.normalize(input.fingerprint);
    const normalizedMac = this.normalizeMac(input.macAddress);

    if (normalizedFingerprint) {
      const matchedRule = FINGERPRINT_RULES.find((rule) =>
        rule.pattern.test(normalizedFingerprint),
      );

      if (matchedRule?.vendor) {
        result.vendor = matchedRule.vendor;
      }

      if (matchedRule?.model) {
        result.model = matchedRule.model;
      }
    }

    if (!result.vendor && normalizedMac) {
      const prefix = normalizedMac.slice(0, 8);
      if (OUI_VENDOR_MAP[prefix]) {
        result.vendor = OUI_VENDOR_MAP[prefix];
      }
    }

    return result;
  }

  private normalize(value?: string | null): string | null {
    const normalized = value?.trim();
    return normalized ? normalized : null;
  }

  private normalizeMac(value?: string | null): string | null {
    const normalized = this.normalize(value);
    if (!normalized) {
      return null;
    }

    const compact = normalized.replace(/[^A-Fa-f0-9]/g, '').toUpperCase();
    if (compact.length < 6) {
      return null;
    }

    return compact.match(/.{1,2}/g)?.join(':') ?? null;
  }
}
