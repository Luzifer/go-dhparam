package dhparam

import "testing"

func TestCheckOwn(t *testing.T) {
	dh, err := Generate(512, 2, nil)
	if err != nil {
		t.Fatalf("Could not generate DH parameters: %s", err)
	}

	errs, ok := dh.Check()
	if !ok {
		t.Fatalf("DH validation was not successful: %#v", errs)
	}
}

func TestOpenSSLGenerated(t *testing.T) {
	tests := map[string]string{
		"2_512bit": `-----BEGIN DH PARAMETERS-----
MEYCQQCv5GjOovf4i4wQbQCHlb4sdf+ImR4o/m8+VeD3TbMIUlarHQAsLgXPQYsE
g3+KzUc1W0W9AE28oTf6c6J/TcS7AgEC
-----END DH PARAMETERS-----`,
		"2_1024bit": `-----BEGIN DH PARAMETERS-----
MIGHAoGBAJ/O4zueSGVilc8xRh8yqIqx2I78lVYX/2NwtkSkY81/r7/cjrbo0bZ0
983B6BzCTJ4BPEpfmZ7IIXC4HhXShzHIXrJO1Cc+7m3041vEhgwyEXRKUbYBbYMm
kWmCXuw4fuMI8cv4+jelYfgPjPG/XzJ0ZcCASDKgAtG4TzG4gDUDAgEC
-----END DH PARAMETERS-----`,
		"2_2048bit": `-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA4OkpmW50f7zVyK0QcZStmT13MbiZndmgP9aky5TiRksr3tmdIx+J
LI8jJD/Ru87hH6XSVNN0zUxPYf5n9U5lfzWwlzT0Rz+T2Ssh0DselobcPWwRMVox
y28szYArdz0/tTyAbNzGMlJOXyKU9LTGZXXz32fllSMbvG+xNFOAA0iKl1O3I5uU
hhVTCorRKs+uwMgjdhRyj/elm/xX4XjxPUB4unhmRBFUVbE3O/1Hoao9rjV0x/Xv
CnrP4fQh75z+DkT4jKfyhHy4bCxLqR1GKkTLdTz213zjpTe58ubdx3GJwPBjCdCB
fMPJHWPjj5gb9JaY+jTjvxVBeP4X4GwpIwIBAg==
-----END DH PARAMETERS-----`,
		"2_4096bit": `-----BEGIN DH PARAMETERS-----
MIICCAKCAgEAqCfqBtydprUAE7+mxo1HSufiaIMq0m0owkECLHpmtLM59WiexTOb
BNMq79N0bYRgHMi0huF3u3f9e0fJw01kNrsZia40G7PuI5jMVx7OvS02//OI950m
XLE3GBRnny60gHwO9CohusjCHNqzBIybbZd4egO5LELU6eSOhNLQ9ENSuQDoEYN6
MjADT2sP5eTq2CshjKTsV/bDcSgkB9EmCPPsYgESyPiIK5Jp5iaqeDBo+nSQyFF6
E9UhY53g8Xh/XAsFFWX2le+KsFO0tA0px1yL8lVPxH7b57UnIgHZHlw5Mf6MM5kr
J2oXyFOUBX2aqZ8ZQLWqOfjuItUUqxyr1rqjFfWZTrpu7OCR8I/lVKlvdDolUnbJ
87GfVrC7q4qnG7u8BAEFFCmJ0JcisOccJBFEWwitKjRxrxUql2gYpr7ry85jy7zK
Aw6i5zuVJhOk+w4O/sSpmY35X0+lGt5mstHD84+er7GVOgfUo8PbqclgU1XyrabA
eHHrmxvwHnOIUEhTl6b/4r0teVh3Xu7aGgoDYijvhYb7nlpSgwTJ5CN8tP75OY9N
KS9NS3uqz0SUoTJNnxgbnpCjwrkJWWaOGwAGs+wXzy0tiA8rWJa+0v//nkSlzi0A
WzAIBihs107JYrgBdiJ/necTNstXo8//wxGIr5Ncc/Xx0056OII0GdMCAQI=
-----END DH PARAMETERS-----`,
		"5_512bit": `-----BEGIN DH PARAMETERS-----
MEYCQQDwi9IfzZY6rnmM757o8+gtl1YH8w3mdMg/JPfy35N5eJhvgx/TDyFuZUD7
5T9I2sypdmbv3jWLbQzTBWFZV9xTAgEF
-----END DH PARAMETERS-----`,
		"5_1024bit": `-----BEGIN DH PARAMETERS-----
MIGHAoGBAOhcZ2xhJuGJsXwhD9WthoJ2yaDTg1UQELgplC48sl9fAhEaWl7tSCSK
kLr5DZu0znHjv9AWf8qMnyRMwDAXx0go3SaqrB+rNQjxNpmgssp841vLLSsttHiP
M1PfJp2GVV8Er5dRnfPOBXvIryO0aRUtjKs2AOqEd0rWKdqQP80XAgEF
-----END DH PARAMETERS-----`,
		"5_2048bit": `-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAp8Oe7MPt+RdKBX2ht+Ok9XpQohaagc6RyyPNUeNTXoKDoCcJu9fk
gEg7EkjcAbjvOXkZhNWCCuXSra3qnjTCKcuvZFIJp5i3pYLlZl9d2qKo72fk25yN
h4HbygtpufYL5PQMvhOGae/+dJyxjprzzQkQAUy6qiWqYEBc+OyCcYGIMjHVcf53
1vg8L5j3k+Pi0aCWZcwxDzJDPfFpG1B3J0ELVZK1eLe4vcKmxBfDbuFyQ1AG22Gh
OIwSXKyK6z5yuU9sZOsire0nnpOYWxE9blg3frfsFgb2bah7YtxQv75PtVYUuVUL
FBUWAa1u8vuIzcZ/tLEADgImJ4TZmrsiLwIBBQ==
-----END DH PARAMETERS-----`,
	}

	for key, encoded := range tests {
		dh, err := Decode([]byte(encoded))
		if err != nil {
			t.Errorf("[%s] Was not able to decode: %s", key, err)
		}

		errs, ok := dh.Check()
		if !ok {
			t.Fatalf("[%s] DH validation was not successful: %#v", key, errs)
		}
	}
}
