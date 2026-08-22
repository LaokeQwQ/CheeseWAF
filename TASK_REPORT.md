# R2-5 Engine Task Report

Status: DONE_WITH_CONCERNS

Implementation commit: `d05a25920b498d3e1c945e1571c671783b07dc4a`

## Finding dispositions

### Section I: engine foundation

1. **Decode depth (resolved).** The default bounded decode depth is now 6 and the hard ceiling is 8. `waf.semantic_policy.decode_depth` accepts 1-8 (0 means default), is validated, survives storage/API round trips, and is wired into each production analyzer. Seven-layer URL encoding and depth clamping have focused tests.
2. **Budget exhaustion fail mode (retained and dynamically verified).** The baseline already provided `auto|open|observe|closed`, strict web-attack policy resolves to `closed`, proxy request metadata carries the resolved policy, and exhausted closed analysis returns a challenge. Existing focused tests were rerun; duplicating this implementation was unnecessary.
3. **Per-request worker pool (resolved).** Multi-detector semantic work now uses one lazily initialized process-shared pool capped at 8 workers. Requests allocate only their result buffer/jobs, not worker goroutines/channels/WaitGroups. A regression warms the pool and proves repeated detection starts no additional semantic workers; race coverage passed.
4. **SQL detection payload size (resolved).** Both libinjection and fallback results truncate `DetectionResult.Payload` to 512 bytes. A 2,097-byte red case now returns at most 512 bytes.

### Section V: engine findings

1. **Simplified libinjection gaps (resolved within reviewed scope).** Added reviewed reachable fingerprints and tokenizer support instead of copying the incompatible upstream table. Repeated bare words remain uncollapsed so `SELECT account FROM users` is distinguishable from benign prose such as `select a theme from the menu`. The rejected broad `kw` fingerprint and full-table copy were not added.
2. **SMIL XSS (resolved).** Added both attribute orders for SVG `animate`/`set`, `attributeName=(xlink:)href`, and `value(s)=javascript:`. Standalone and analyzer execution-context coverage is pinned.
3. **Broad RCE arithmetic patterns (resolved).** Removed bare `$((number op number))` detection and the unbounded backtick/`$()` arithmetic pattern. Existing command-substitution and shell-control patterns continue to cover executable commands; benign arithmetic in an execution-shaped field now passes.

### Section VI: libinjection details

1. **Dead SQL tokens (resolved).** Equal numeric/quoted literals emit `t`; `?`, `$number`, and `:name` placeholders emit `v`. `&t` is a reviewed high-signal tautology window.
2. **Unreachable semicolon fingerprints (resolved).** Removed `s;U`, `s;E`, and `s;k`; no semicolon token was introduced because existing stacked-query behavior is covered without expanding the alphabet.
3. **XSS dead-token confusion (resolved).** Removed the unused XSS token constants and corrected the API comment to state that XSS uses contextual matching rather than token fingerprints.
4. **Reviewed fingerprints (resolved).** Added and tested `kc`, `nc`, `Uwk`, `Bn`, `fws`, `Ew`, and `o(`. Added `Ef` for `EXEC XP_CMDSHELL` after `XP_CMDSHELL` is correctly promoted to function token `f`.
5. **Keywords/functions/placeholders (resolved).** Added `FROM`, `WHERE`, `TABLE_NAME`, and `NULL` as keywords; added `LOAD_FILE`, `XP_CMDSHELL`, `DBMS_SQL`, `CHAR`, `UNHEX`, `HEX`, and `SQLCODE` as functions; added all reviewed placeholder forms.

## TDD evidence

Red commands (all exited 1 for the expected audited behavior after `GOCACHE` was moved into the permitted temp path):

```text
env GOCACHE=/private/tmp/cw-r2-engine-gocache go test ./internal/engine -run 'TestSQL(LibinjectionReviewedFingerprints|TokenizerEmitsTautologyAndVariableTokens|LibinjectionKeepsBroadKeywordWordPairBenign)$' -count=1
env GOCACHE=/private/tmp/cw-r2-engine-gocache go test ./internal/engine/decoder -run 'TestDeepDecodeRevealsSevenURLLayers$' -count=1
env GOCACHE=/private/tmp/cw-r2-engine-gocache go test ./internal/engine/semantic -run 'Test(XSSDetectorBlocksSMILAnimationHref|RCEDetectorKeepsBenignCommandDocumentationClean|SQLDetectorCapsDetectionPayload)$' -count=1
```

Observed red failures included missing `kc/Uwk/Bn/fws/Ew`, unreachable tautology tokens, seven-layer decoding leaving `%3Cscript...`, benign `$((12 + 30))` detected as RCE, and SQL evidence length 2,097.

Green focused commands (all exited 0):

```text
env GOCACHE=/private/tmp/cw-r2-engine-gocache go test ./internal/engine -run 'Test(SQLLibinjectionReviewedFingerprints|SQLTokenizerEmitsTautologyAndVariableTokens|SQLTokenizerClassifiesReviewedFunctions|SQLTokenizerClassifiesReviewedKeywords|SQLLibinjectionKeepsBroadKeywordWordPairBenign|PipelineReusesSharedSemanticWorkers|PipelineSemanticGroupConcurrentMerge|PipelineBudgetExhaustedPolicies)$' -count=1
env GOCACHE=/private/tmp/cw-r2-engine-gocache go test ./internal/engine/decoder -run 'Test(DeepDecodeRevealsSevenURLLayers|DecodeWithDepthUsesDefaultAndHardCeiling|DeepDecodeRevealsNestedBase64AndURLPayload)$' -count=1
env GOCACHE=/private/tmp/cw-r2-engine-gocache go test ./internal/engine/semantic -run 'Test(XSSDetectorBlocksSMILAnimationHref|RCEDetectorKeepsBenignCommandDocumentationClean|SQLDetectorCapsDetectionPayload|DecodeVariantsHonorConfiguredDepth|SQLDetectorKeepsBenignEncodedQueryClean|SQLDetectorKeepsBenignDocumentationClean)$' -count=1
```

## Final verification

All listed commands exited 0:

```text
env GOCACHE=/private/tmp/cw-r2-engine-gocache go test ./internal/engine/semantic -run 'Test(AnalyzerCuratedExternalCorpus|AnalyzerReadinessMatrix|AnalyzerReadinessBenignMatrix|FPGateReport)$' -count=1
env GOCACHE=/private/tmp/cw-r2-engine-gocache go test ./internal/engine/... ./internal/config/... -short -count=1
env GOCACHE=/private/tmp/cw-r2-engine-gocache go test -race ./internal/engine -run 'Test(PipelineReusesSharedSemanticWorkers|PipelineSemanticGroupConcurrentMerge|PipelineBudgetExhaustedPolicies)$' -count=1
env GOCACHE=/private/tmp/cw-r2-engine-gocache go test ./internal/storage -run 'TestSiteConfigRoundTripPreservesNoSQLSemanticSwitch$' -count=1
env GOCACHE=/private/tmp/cw-r2-engine-gocache go test ./internal/cli -run 'TestBuildPipeline(UsesSingleSemanticAnalyzerPath|WiresRCEUmbrellaCategories|HonorsNoSQLSemanticSwitch|HonorsSSTISemanticSwitch|ScopesSemanticSwitchesPerSite|ScopesCustomRulesPerSite)$' -count=1
```

The corpus/FP gate reported zero benign false positives and all curated attack cases detected. `git diff --check` was clean before commit. The complete implementation diff was reviewed. `deepseek_822_tasks.md` was not edited.

## Concerns

The unrestricted full `go test ./internal/cli` suite could not complete in the managed sandbox because an unrelated `httptest.NewServer` test was denied permission to bind `[::1]:0`. All CLI tests covering the changed pipeline wiring passed. No other concerns remain.
