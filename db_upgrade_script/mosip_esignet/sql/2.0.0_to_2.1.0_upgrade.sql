-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

\c mosip_esignet

-- Native SSO for mobile apps: consent reused from the app that minted the device secret is
-- recorded in consent_history with the client it was reused from.
ALTER TABLE esignet.consent_history ADD COLUMN IF NOT EXISTS reused_from_client_id VARCHAR(256);
