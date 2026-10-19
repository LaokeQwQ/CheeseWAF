package engine

import (
	"context"
	"testing"
)

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

func TestCanceledSemanticSubmissionReleasesSitePermitForRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	jobs := make(chan semanticJob)
	for i := 0; i < maxSemanticJobsPerSite; i++ {
		token, admitted := semanticSiteAdmissions.acquire("cancel-retry-site")
		if !admitted {
			t.Fatalf("site permit leaked before canceled submission %d", i)
		}
		submitted, overloaded := enqueueSemanticJob(ctx, jobs, semanticJob{admission: token})
		if submitted || overloaded {
			t.Fatalf("canceled submission result submitted=%v overloaded=%v", submitted, overloaded)
		}
	}
	for range maxSemanticJobsPerSite {
		token, admitted := semanticSiteAdmissions.acquire("cancel-retry-site")
		if !admitted {
			t.Fatal("canceled submissions leaked semantic site permits")
		}
		token.release()
	}
}
