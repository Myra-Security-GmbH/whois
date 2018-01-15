package whois

const (
	// RecordTypeTechC record type for technical
	RecordTypeTechC = 1

	// RecordTypeAdminC record type for admins
	RecordTypeAdminC = 2

	// RecordTypeOwner record type for owner
	RecordTypeOwner = 3

	// RecordTypeNetwork record type for a network
	RecordTypeNetwork = 4

	// RecordTypeDomain record type for a domain
	RecordTypeDomain = 5

	// RecordTypeOther for all other records
	RecordTypeOther = 256
)

//
// QueryResult contains raw and parsed information of a whois query
//
type QueryResult struct {
	target  string
	records []QueryRecord
	raw     []byte
}

//
// QueryRecord containing parsed record data and additional meta data
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

//
// Target returns the queried target (hostname or IP)
//
func (q QueryResult) Target() string {
	return q.target
}

//
// Data returns the parsed data map
//
func (r QueryRecord) Data() map[string]string {
	return r.data
}

//
// RecordType returns the record type
//
func (r QueryRecord) RecordType() int {
	return r.recordType
}
