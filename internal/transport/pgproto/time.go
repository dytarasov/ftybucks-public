package pgproto

import "time"

// pgEpoch is 2000-01-01 00:00:00 UTC — PostgreSQL's epoch.
var pgEpoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// pgTimestamp returns microseconds since the PostgreSQL epoch (2000-01-01 00:00:00 UTC).
func pgTimestamp() int64 {
	return time.Since(pgEpoch).Microseconds()
}
