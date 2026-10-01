package redact

import "testing"

func TestPartialMasking(t *testing.T) {
	cases := map[string]string{ // label -> input : expected via maskValue
	}
	_ = cases
	checks := []struct{ label, in, want string }{
		{"phone", "+7 916 555-01-32", "+7916*32"},
		{"ip", "192.168.0.1", "192.*.*.1"},
		{"ip", "10.113.48.48", "10.*.*.48"},
		{"full_name", "Иванов Иван Иванович", "Ив* И* И*"},
		{"full_name", "John Smith", "Jo* S*"},
		{"email", "john.doe@example.com", "j*@example.com"},
		{"credit_card", "4111 1111 1111 1111", "*1111"},
		{"aws_access_key", "AKIAIOSFODNN7EXAMPLE", "[REDACTED:aws_access_key]"},
	}
	for _, c := range checks {
		if got := maskValue(c.label, c.in); got != c.want {
			t.Errorf("maskValue(%s,%q) = %q, want %q", c.label, c.in, got, c.want)
		}
	}
}
