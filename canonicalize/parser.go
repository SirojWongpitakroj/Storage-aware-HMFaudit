package canonicalize

import (
	"encoding/json"
	"fmt"
)

func (r *DatasetReader) parse(logBytes []byte) error {
	err := json.Unmarshal(logBytes, r.CurrLog)
	if err != nil {
		return fmt.Errorf("error parsing associated data from bytes to json")
	}
	return nil
}
