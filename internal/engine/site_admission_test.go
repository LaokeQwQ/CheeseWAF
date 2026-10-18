package engine

import "testing"

func TestSemanticSiteAdmissionLeavesQueueCapacityForOtherSites(t *testing.T) {
	tokens := make([]siteAdmissionToken, 0, maxSemanticJobsPerSite)
	for i := 0; i < maxSemanticJobsPerSite; i++ {
		token, admitted := semanticSiteAdmissions.acquire("noisy-site")
		if !admitted {
			t.Fatalf("same-site semantic admission rejected slot %d/%d", i+1, maxSemanticJobsPerSite)
		}
		tokens = append(tokens, token)
	}
	defer func() {
		for _, token := range tokens {
			token.release()
		}
	}()
	if _, admitted := semanticSiteAdmissions.acquire("noisy-site"); admitted {
		t.Fatal("same site exceeded its semantic queue quota")
	}
	quiet, admitted := semanticSiteAdmissions.acquire("quiet-site")
	if !admitted {
		t.Fatal("quiet site lost semantic queue capacity to noisy site")
	}
	quiet.release()
}
