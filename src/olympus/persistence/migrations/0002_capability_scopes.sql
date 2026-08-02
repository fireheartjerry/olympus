-- Capability scopes: the constraints a grant carries beyond its name.
--
-- `system.inspect@1` needed none; it reads fixed counters, so granting it says
-- everything. `fs.read@1` does not work that way -- the name alone would mean
-- "read any file on that machine" -- so the bound travels with the grant, is
-- minted with the enrollment token, and is owned by the control plane.
--
-- Defaulting to an empty object is safe because an absent scope never means
-- "everything": a capability that requires one is refused at dispatch when it
-- has none. Existing rows therefore keep exactly the authority they had.

ALTER TABLE enrollment_tokens
    ADD COLUMN IF NOT EXISTS capability_scopes JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS capability_scopes JSONB NOT NULL DEFAULT '{}'::jsonb;
