import * as cryptoNode from 'crypto';

export class CryptoUtils {
  static sha256(data: string): string {
    return cryptoNode.createHash('sha256').update(data).digest('hex');
  }

  static hmacSha256(key: string | Buffer, data: string): Buffer {
    return cryptoNode.createHmac('sha256', key).update(data).digest();
  }

  static hmacSha256Hex(key: string | Buffer, data: string): string {
    return cryptoNode.createHmac('sha256', key).update(data).digest('hex');
  }
}

export const crypto = CryptoUtils;
