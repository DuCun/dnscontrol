package huaweicloud

import (
	"testing"

	"github.com/DNSControl/dnscontrol/v4/models"
)

func makeRC(rtype, label, target string, metadata map[string]string) *models.RecordConfig {
	rc := &models.RecordConfig{
		Type:     rtype,
		Metadata: metadata,
	}
	rc.SetLabel(label, "example.com")
	rc.MustSetTarget(target)
	return rc
}

func TestAuditRecordsScopedCNAMEs(t *testing.T) {
	tests := []struct {
		name      string
		records   []*models.RecordConfig
		wantCount int
	}{
		{
			name: "single cname",
			records: []*models.RecordConfig{
				makeRC("CNAME", "www", "a.example.net.", nil),
			},
			wantCount: 0,
		},
		{
			name: "same name different line allowed",
			records: []*models.RecordConfig{
				makeRC("CNAME", "www", "a.example.net.", map[string]string{"hw_line": "default_view"}),
				makeRC("CNAME", "www", "b.example.net.", map[string]string{"hw_line": "CN"}),
			},
			wantCount: 0,
		},
		{
			name: "same name different rrset key allowed",
			records: []*models.RecordConfig{
				makeRC("CNAME", "www", "a.example.net.", map[string]string{"hw_rrset_key": "group-a"}),
				makeRC("CNAME", "www", "b.example.net.", map[string]string{"hw_rrset_key": "group-b"}),
			},
			wantCount: 0,
		},
		{
			name: "same name same routing scope rejected",
			records: []*models.RecordConfig{
				makeRC("CNAME", "www", "a.example.net.", map[string]string{"hw_line": "CN", "hw_weight": "10"}),
				makeRC("CNAME", "www", "b.example.net.", map[string]string{"hw_line": "CN", "hw_weight": "10"}),
			},
			wantCount: 1,
		},
		{
			name: "same name default routing scope rejected",
			records: []*models.RecordConfig{
				makeRC("CNAME", "www", "a.example.net.", nil),
				makeRC("CNAME", "www", "b.example.net.", nil),
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := AuditRecords(tt.records)
			if len(errs) != tt.wantCount {
				t.Fatalf("AuditRecords() returned %d errors, want %d: %v", len(errs), tt.wantCount, errs)
			}
		})
	}
}
