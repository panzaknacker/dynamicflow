package application

// validateSystemExpectation binds a confirmed plan to its displayed system.
// An omitted expectation is suitable for an explicit immediate CLI command;
// plan/confirmation adapters must carry the exact system ID into execution.
func validateSystemExpectation(meta RequestMeta, activeSystemID string) error {
	if meta.ExpectedSystemID != "" && meta.ExpectedSystemID != activeSystemID {
		return appError("system_conflict", 6, "The active system differs from the confirmed Control plan.", "Refresh the dashboard and review a new plan for the intended system.", nil)
	}
	return nil
}

func (application *Application) checkSystemExpectation(meta RequestMeta) error {
	if meta.ExpectedSystemID == "" {
		return nil
	}
	if application == nil || application.systems == nil {
		return appError("application_unavailable", 3, "Dynamicflow application state is unavailable.", "Repair the private state directory.", nil)
	}
	active, err := application.systems.Active()
	if err != nil {
		return appError("system_state", 3, "The active system binding is unavailable.", "Recover the private system registry.", err)
	}
	return validateSystemExpectation(meta, active.ID)
}
