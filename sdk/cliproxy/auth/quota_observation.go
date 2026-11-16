package auth

// A quota observation uses preparation's content merge, with only its newer
// quota snapshot added. It is not evidence of a credential refresh.
func mergeQuotaObservedAuth(base, existing, updated *Auth) *Auth {
	merged := MergePreparedAuth(base, existing, updated)
	merged.Quota = mergeQuotaObservation(merged.Quota, updated.Quota)
	return merged
}

func preserveQuotaObservationLifecycle(mode updateAuthMode, updated, existing *Auth) {
	if mode != updateModeQuotaObservation {
		return
	}
	updated.RefreshFailures = existing.RefreshFailures
	updated.RefreshError = cloneError(existing.RefreshError)
	updated.NextRefreshAfter = existing.NextRefreshAfter
	updated.LastRefreshedAt = existing.LastRefreshedAt
	updated.RequiresSignIn = existing.RequiresSignIn
	updated.RenewalVerified = existing.RenewalVerified
	updated.LastRenewalVerifiedAt = existing.LastRenewalVerifiedAt
	updated.RenewalWarnedRefreshToken = existing.RenewalWarnedRefreshToken
	updated.RenewalEventAt = existing.RenewalEventAt
	updated.AdoptedAt = existing.AdoptedAt
	updated.AdoptedGrantHash = existing.AdoptedGrantHash
	updated.InferenceVerified = existing.InferenceVerified
	updated.LastInferenceVerifiedAt = existing.LastInferenceVerifiedAt
	updated.RejectedAccessToken = existing.RejectedAccessToken
	updated.RejectedSIWCAccessToken = existing.RejectedSIWCAccessToken
	updated.RejectedRefreshToken = existing.RejectedRefreshToken
	updated.RejectedSIWCRefreshToken = existing.RejectedSIWCRefreshToken
}
