package conjurapi

const MinVersion = "1.23.0"

type ClientV2 struct {
	*Client
	default_max_entries_read_limit uint
}
