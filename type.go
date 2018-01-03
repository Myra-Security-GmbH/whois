package whois

const (
	// RecordTypeTechC record type for technical
	RecordTypeTechC = 1

	// RecordTypeAdminC record type for admins
	RecordTypeAdminC = 2

	// RecordTypeOwner record type for owner
	RecordTypeOwner = 3

	// RecordTypeOther for all other records
	RecordTypeOther = 256
)

//
// QueryRecord ...
//
type QueryResult struct {
	records []QueryRecord
	raw     []byte
}

//
// QueryRecord ...
//
type QueryRecord struct {
	data       map[string]string
	recordType int
}

//
// RawOutput returns the raw output
//
func (q QueryResult) RawOutput() []byte {
	return q.raw
}

//
// Records returns a list of all parsed records.
//
func (q QueryResult) Records() []QueryRecord {
	return q.records
}
