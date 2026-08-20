# Gateway load-test methodology

Run `npm run test:gateway-load` after building. The test sends 100 concurrent
cheap liveness requests to a loopback gateway while the proving pool is
configured with one worker and a bounded queue. It asserts every liveness
response remains successful and that aggregate metrics contain no request,
user, or proof labels. The printed elapsed time is a local observation only; it
is not a capacity promise and must not be used as a production SLO without
repeating the test on the target runtime and network path.
