const crypto = require('crypto');

class InitDataParser {
  static parse(initDataQuery) {
    const params = new URLSearchParams(initDataQuery);
    const hash = params.get('hash') || '';
    const auth_date = parseInt(params.get('auth_date') || '0', 10);
    const userStr = params.get('user') || '{}';

    let user;
    try {
      user = JSON.parse(userStr);
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
}

module.exports = { InitDataParser };
