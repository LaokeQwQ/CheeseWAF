package engine

import (
	"strings"
	"testing"
)

func TestSQLLibinjectionReviewedFingerprints(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		window  string
	}{
		{name: "keyword comment", payload: "SELECT/**/password", window: "kc"},
		{name: "number comment", payload: "1 OR 1=2-- trailing", window: "nc"},
		{name: "union all select", payload: "UNION ALL SELECT", window: "Uwk"},
		{name: "order by ordinal", payload: "ORDER BY 9", window: "Bn"},
		{name: "waitfor delay", payload: "WAITFOR DELAY '00:00:05'", window: "fws"},
		{name: "exec procedure", payload: "EXEC sp_configure", window: "Ew"},
		{name: "exec dangerous function", payload: "EXEC xp_cmdshell", window: "Ef"},
		{name: "operator subquery", payload: "||(SELECT secret FROM users)", window: "o("},
		{name: "select from", payload: "SELECT account FROM users", window: "kwkw"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp, detected := SQLLibinjectionFingerprint(tt.payload)
			if !detected {
				t.Fatalf("payload was not detected; fingerprint=%q", fp)
			}
			if !strings.Contains(fp, tt.window) {
				t.Fatalf("fingerprint=%q does not contain reviewed window %q", fp, tt.window)
			}
		})
	}
}

func TestSQLTokenizerClassifiesReviewedFunctions(t *testing.T) {
	for _, name := range []string{"LOAD_FILE", "XP_CMDSHELL", "DBMS_SQL", "CHAR", "UNHEX", "HEX", "SQLCODE"} {
		if token, _ := nextToken(name); token != tkSQLFunction {
			t.Fatalf("%s token=%q, want function", name, token)
		}
	}
}

func TestSQLTokenizerClassifiesReviewedKeywords(t *testing.T) {
	for _, name := range []string{"FROM", "WHERE", "TABLE_NAME", "NULL"} {
		if token, _ := nextToken(name); token != tkSQLKeyword {
			t.Fatalf("%s token=%q, want keyword", name, token)
		}
	}
}

func TestSQLTokenizerEmitsTautologyAndVariableTokens(t *testing.T) {
	if fp := fingerprint(tokenizeSQL("1 OR 1=1")); !strings.ContainsRune(fp, tkSQLTautology) {
		t.Fatalf("tautology token is unreachable; fingerprint=%q", fp)
	}
	for _, payload := range []string{"SELECT ?", "SELECT $1", "SELECT :account_id"} {
		if fp := fingerprint(tokenizeSQL(payload)); !strings.ContainsRune(fp, tkSQLVariable) {
			t.Fatalf("variable token is unreachable for %q; fingerprint=%q", payload, fp)
		}
	}
}

func TestSQLLibinjectionKeepsBroadKeywordWordPairBenign(t *testing.T) {
	if fp, detected := SQLLibinjectionFingerprint("select newsletter preferences"); detected {
		t.Fatalf("broad keyword-word pair must remain benign; fingerprint=%q", fp)
	}
}
