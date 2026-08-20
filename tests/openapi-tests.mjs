import assert from 'node:assert/strict';
import fs from 'node:fs';

const spec = JSON.parse(fs.readFileSync('openapi/zk-tele-auth.openapi.json', 'utf8'));
assert.equal(spec.openapi, '3.1.0');
for (const route of ['/v1/authentications', '/authenticate', '/livez', '/readyz', '/metrics', '/v1/purchase-authorizations']) {
  assert.ok(spec.paths[route], `OpenAPI route missing: ${route}`);
}
assert.equal(spec.paths['/authenticate'].post.deprecated, true);
assert.equal(spec.paths['/v1/purchase-authorizations'].post.deprecated, true);
assert.equal(spec.components.schemas.AuthenticationRequest.additionalProperties, false);
assert.equal(spec.components.schemas.AuthenticationRequest.properties.initData.maxLength, 32768);
assert.equal(spec.components.schemas.AuthenticationResponse.properties.success.const, true);
assert.equal(spec.components.schemas.GatewayError.properties.requestId.format, 'uuid');
assert.equal(spec.components.responses.ProverBusy.headers['Retry-After'].schema.type, 'string');

const serverSource = fs.readFileSync('src/gateway/server.ts', 'utf8');
for (const route of ['/v1/authentications', '/authenticate', '/v1/purchase-authorizations', '/livez', '/readyz', '/metrics']) {
  assert.match(serverSource, new RegExp(route.replaceAll('/', '\\/')));
}
console.log('OpenAPI contract tests: passed');
