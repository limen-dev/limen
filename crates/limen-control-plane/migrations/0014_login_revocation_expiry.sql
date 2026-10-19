-- A revoked login only needs to be remembered while its certificate could
-- still be used, and the certificate lifetime is configurable (up to weeks),
-- so a fixed window can forget a logout early. Keep each until its certificate
-- expires. Rows from before this column fall back to a month.
ALTER TABLE login_revocations ADD COLUMN expires_at TIMESTAMPTZ;
