package huaweicloud

import (
	"fmt"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/rejectif"
)

// AuditRecords returns a list of errors corresponding to the records
// that aren't supported by this provider.  If all records are
// supported, an empty list is returned.
func AuditRecords(records []*models.RecordConfig) []error {
	a := rejectif.Auditor{}
	a.Add("MX", rejectif.MxNull)              // Last verified 2024-06-14
	a.Add("TXT", rejectif.TxtHasBackslash)    // Last verified 2024-06-14
	a.Add("TXT", rejectif.TxtHasDoubleQuotes) // Last verified 2024-06-14

	errs := a.Audit(records)
	errs = append(errs, rejectDuplicateScopedCNAMEs(records)...)
	return errs
}

func rejectDuplicateScopedCNAMEs(records models.Records) (errs []error) {
	seen := map[string]bool{}
	for _, rc := range records {
		if rc.Type != "CNAME" {
			continue
		}
		scopeKey := rc.GetLabelFQDN() + "|" + scopedRoutingKey(rc)
		if seen[scopeKey] {
			errs = append(errs, fmt.Errorf("CNAME records must be unique per hw_line, hw_weight, and hw_rrset_key: %s", rc.GetLabelFQDN()))
			continue
		}
		seen[scopeKey] = true
	}
	return errs
}

func scopedRoutingKey(rc *models.RecordConfig) string {
	weight := rc.Metadata[metaWeight]
	line := rc.Metadata[metaLine]
	key := rc.Metadata[metaKey]
	if weight == "" {
		weight = defaultWeight
	}
	if line == "" {
		line = defaultLine
	}
	return weight + "|" + line + "|" + key
}
