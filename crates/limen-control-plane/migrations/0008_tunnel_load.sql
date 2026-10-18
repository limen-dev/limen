-- Worker load as the proxy holding each tunnel last reported it, so other
-- proxies routing through peers can pick the less loaded worker (Phase 5).
-- 0/0 means unknown (proxies or workers before Phase 5): no cap.
ALTER TABLE tunnels
    ADD COLUMN active_sessions INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN max_sessions    INTEGER NOT NULL DEFAULT 0;
