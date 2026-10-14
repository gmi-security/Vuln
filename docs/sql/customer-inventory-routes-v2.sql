-- Explicit additive extension after customer-inventory-routes.sql.
-- No approvals are created or enabled; existing review constraints remain.
BEGIN;
ALTER TABLE customer_inventory_routes DROP CONSTRAINT customer_inventory_routes_provider_check;
ALTER TABLE customer_inventory_routes ADD CONSTRAINT customer_inventory_routes_provider_check
  CHECK(provider IN ('automate','intune','tidal','crowdstrike'));
-- One Falcon connection cannot claim multiple CIDs/customer destinations.
CREATE UNIQUE INDEX customer_inventory_route_falcon_connection ON customer_inventory_routes(candidate_id)
  WHERE provider='crowdstrike' AND enabled;
COMMIT;
