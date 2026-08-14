# Contract composition boundary

The generated verifier core proves the Priva circuit relation. The wrapper is a cryptographic test/deployment harness and intentionally does not implement purchase economics. A production `priva_purchase_launchpad.tolk` must be added only after operator-approved asset/price/cap/recipient/bounce policy exists. `npm run check:priva-composition` fails closed until the real launchpad and independent review record are present.

