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
// QueryResult struct
//
type QueryResult struct {
	records []QueryRecord
	raw     []byte
}

//
// QueryRecord struct
//
type QueryRecord struct {
	data       map[string]string
	recordType int
}

//
// NewQueryResult creates and returns a new QueryResult
//
func NewQueryResult(in []byte) QueryResult {
	return QueryResult{
		raw:     in,
		records: []QueryRecord{},
	}
}

//
// NewQueryRecord creates and returns a new QueryRecord
//
func NewQueryRecord(data map[string]string, recordType int) QueryRecord {
	return QueryRecord{
		data:       data,
		recordType: recordType,
	}
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
