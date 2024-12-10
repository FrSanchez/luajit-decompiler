return {
	postgres = {
		up = [[
      -- add rbac_user_name,request_source to audit_requests
      DO $$
        BEGIN
        ALTER TABLE IF EXISTS ONLY "audit_requests" ADD COLUMN "rbac_user_name" TEXT;
        ALTER TABLE IF EXISTS ONLY "audit_requests" ADD COLUMN "request_source" TEXT;
        EXCEPTION WHEN duplicate_column THEN
          -- Do nothing, accept existing state
        END;
      $$;
    ]]
	}
}
