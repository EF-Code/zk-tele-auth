const crypto = require('crypto');

class NullifierDeriver {
  static deriveNullifier(userId, appDomain, salt = 'zk-tele-auth-v1') {
    const raw = `${userId}:${appDomain.toLowerCase().trim()}:${salt}`;
    return crypto.createHash('sha256').update(raw).digest('hex');
  }

  static hashAppDomain(appDomain) {
    const hex = crypto.createHash('sha256').update(appDomain.toLowerCase().trim()).digest('hex');
    return BigInt('0x' + hex.substring(0, 16)).toString();
  }
}

module.exports = { NullifierDeriver };
