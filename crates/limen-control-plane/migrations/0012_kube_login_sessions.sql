-- Group a user's Kubernetes requests into one console session per login and
-- cluster (ADR-0038), the way a database session groups its statements. The
-- id is derived from the login and the cluster by the projection, so any
-- order of delivery agrees; requests from before workers named the login
-- have none.
ALTER TABLE kube_requests ADD COLUMN login_session UUID;
CREATE INDEX kube_requests_login_session ON kube_requests (login_session, at) WHERE login_session IS NOT NULL;
