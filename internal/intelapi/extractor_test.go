package intelapi

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
)

func TestAdvisoryExtractorPHP2ShellEvidence(t *testing.T) {
	document := intel.Document{
		Title: "CVE-2025-1234 PHP2Shell",
		Text: `Exploit: POST /uploads/index.php with multipart/form-data and ` +
			`PHP_SESSION_UPLOAD_PROGRESS. The PHPSESSID cookie is returned. ` +
			`Nested parameter a[b][c][d]=1. HTTP/1.1 200 OK. ` +
			`Set-Cookie: PHPSESSID=` + oversizedValue(),
		CodeBlocks: []string{`<?php system($_GET["cmd"]); ?>`, `O:8:"stdClass":1:{s:1:"a";i:1;}`},
	}
	item := intel.Item{
		ID:       "item-test",
		SourceID: "src-test",
		Products: []string{"php"},
		References: []string{
			"https://advisory.example.test/CVE-2025-1234",
		},
	}
	extraction, err := NewAdvisoryExtractor().Extract(context.Background(), item, document)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(extraction.CVEIDs) != 1 || extraction.CVEIDs[0] != "CVE-2025-1234" {
		t.Fatalf("cve ids=%v", extraction.CVEIDs)
	}
	if extraction.Request.Method != "POST" || extraction.Request.Path != "/uploads/index.php" {
		t.Fatalf("request method=%q path=%q", extraction.Request.Method, extraction.Request.Path)
	}
	if extraction.Request.ContentType != "multipart/form-data" {
		t.Fatalf("content type=%q", extraction.Request.ContentType)
	}
	if !extraction.Request.UploadProgress || extraction.Request.SessionParameter != intel.MultipartProgressMarker {
		t.Fatalf("upload progress=%v session=%q", extraction.Request.UploadProgress, extraction.Request.SessionParameter)
	}
	if !extraction.Request.NestedArrays || len(extraction.Request.ParameterNames) != 1 || extraction.Request.ParameterNames[0] != "a" {
		t.Fatalf("nested arrays=%v params=%v", extraction.Request.NestedArrays, extraction.Request.ParameterNames)
	}
	if len(extraction.Request.Markers) != 2 {
		t.Fatalf("markers=%v", extraction.Request.Markers)
	}
	if !extraction.Response.OversizedSessionCookie {
		t.Fatal("expected oversized session cookie evidence")
	}
	if len(extraction.Response.StatusCodes) != 1 || extraction.Response.StatusCodes[0] != 200 {
		t.Fatalf("status codes=%v", extraction.Response.StatusCodes)
	}
	if len(extraction.Response.HeaderNames) != 1 || extraction.Response.HeaderNames[0] != "Set-Cookie" {
		t.Fatalf("headers=%v", extraction.Response.HeaderNames)
	}
	if extraction.Confidence <= 0 || extraction.Confidence > 1 {
		t.Fatalf("confidence=%v", extraction.Confidence)
	}
	if err := intel.ValidateExtraction(extraction); err != nil {
		t.Fatalf("extraction must validate: %v", err)
	}

	again, err := NewAdvisoryExtractor().Extract(context.Background(), item, document)
	if err != nil {
		t.Fatalf("second extract: %v", err)
	}
	if !reflect.DeepEqual(extraction, again) {
		t.Fatalf("extraction is not deterministic:\n%#v\n%#v", extraction, again)
	}
}

func TestAdvisoryExtractorMultipartSession(t *testing.T) {
	document := intel.Document{
		Title: "PHPSESSID exposure",
		Text:  "The application accepts a multipart/form-data body carrying PHPSESSID.",
	}
	extraction, err := NewAdvisoryExtractor().Extract(context.Background(), intel.Item{ID: "item-1", SourceID: "src-test"}, document)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if extraction.Request.SessionParameter != intel.DefaultSessionParameter {
		t.Fatalf("session parameter=%q", extraction.Request.SessionParameter)
	}
	if extraction.Request.UploadProgress || extraction.Request.NestedArrays || len(extraction.Request.Markers) != 0 {
		t.Fatalf("unexpected shape: %+v", extraction.Request)
	}
}

func TestAdvisoryExtractorSessionOnlyIsNotASafeShape(t *testing.T) {
	document := intel.Document{
		Title: "PHPSESSID mention",
		Text:  "The application documents PHPSESSID in its cookie reference.",
	}
	_, err := NewAdvisoryExtractor().Extract(context.Background(), intel.Item{ID: "item-1", SourceID: "src-test"}, document)
	if !errors.Is(err, intel.ErrNoSafeRule) {
		t.Fatalf("expected ErrNoSafeRule, got %v", err)
	}
}

func TestAdvisoryExtractorRejectsVagueAdvisory(t *testing.T) {
	document := intel.Document{
		Title: "Quarterly newsletter",
		Text:  "Our team shipped a new dashboard. No security content here.",
	}
	_, err := NewAdvisoryExtractor().Extract(context.Background(), intel.Item{ID: "item-1", SourceID: "src-test"}, document)
	if !errors.Is(err, intel.ErrNoSafeRule) {
		t.Fatalf("expected ErrNoSafeRule, got %v", err)
	}
}

func TestAdvisoryExtractorHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewAdvisoryExtractor().Extract(ctx, intel.Item{ID: "item-1", SourceID: "src-test"}, intel.Document{Text: "PHPSESSID"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func oversizedValue() string {
	const value = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	repeated := ""
	for len(repeated) < 210 {
		repeated += value
	}
	return repeated[:210]
}
