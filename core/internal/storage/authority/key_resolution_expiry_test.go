package authority

import "testing"

func TestVerifySignalLogicalClockAgainstKeyExpiry(t *testing.T) {
	t.Parallel()
	exp := uint64(10)
	cases := []struct {
		name   string
		lc     uint64
		expiry *uint64
		wantOK bool
	}{
		{"nil expiry always ok", 100, nil, true},
		{"within expiry", 5, &exp, true},
		{"at expiry", 10, &exp, true},
		{"past expiry", 11, &exp, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifySignalLogicalClockAgainstKeyExpiry(tc.lc, tc.expiry)
			if tc.wantOK && err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !tc.wantOK {
				if err == nil {
					t.Fatal("expected error")
				}
				f, ok := FailureAs(err)
				if !ok || f.Code != "SIGNAL_AUTH_FAILURE" {
					t.Fatalf("want SIGNAL_AUTH_FAILURE, got %v", err)
				}
			}
		})
	}
}
