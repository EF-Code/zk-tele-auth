import { crypto } from './crypto-utils.js';
import { ParsedTelegramUser, TelegramInitDataRaw } from './types.js';

export class InitDataParser {
  /**
   * Parse Telegram WebApp initData query string into structured object
   * @param initDataQuery Query string passed from Telegram MiniApp
   * @returns { raw: TelegramInitDataRaw, user: ParsedTelegramUser }
   */
  static parse(initDataQuery: string): { raw: TelegramInitDataRaw; user: ParsedTelegramUser } {
    const params = new URLSearchParams(initDataQuery);
    const hash = params.get('hash') || '';
    const authDateString = params.get('auth_date') || '';
    const auth_date = /^(0|[1-9][0-9]*)$/.test(authDateString) ? Number(authDateString) : Number.NaN;
    const userStr = params.get('user') || '{}';

    let user: ParsedTelegramUser;
    try {
      const decoded = JSON.parse(userStr);
      user = decoded && typeof decoded === 'object' && !Array.isArray(decoded) ? decoded : { id: 0 };
    } catch {
      user = { id: 0 };
    }

    return {
      raw: {
        query_id: params.get('query_id') || undefined,
        user: userStr,
        auth_date,
        hash
      },
      user
    };
  }

  /**
   * Validate Telegram initData signature against Bot Token
   * @param initDataQuery Raw initData query string
   * @param botToken Telegram Bot Token
   * @returns boolean
   */
  static validateSignature(initDataQuery: string, botToken: string): boolean {
    const params = new URLSearchParams(initDataQuery);
    const hash = params.get('hash');
    if (!hash) return false;

    params.delete('hash');

    // Sort parameters alphabetically
    const dataCheckArr: string[] = [];
    params.sort();
    params.forEach((value, key) => {
      dataCheckArr.push(`${key}=${value}`);
    });
    const dataCheckString = dataCheckArr.join('\n');

    // Derive secret key: HMAC_SHA256("WebAppData", botToken)
    const secretKey = crypto.hmacSha256('WebAppData', botToken);
    const calculatedHash = crypto.hmacSha256Hex(secretKey, dataCheckString);

    return crypto.timingSafeHexEqual(calculatedHash, hash);
  }
}
