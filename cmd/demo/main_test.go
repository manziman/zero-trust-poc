package main

import (
	"testing"
)

func TestValidateRecordIDsRejectsRowsOutsideExpectedRLSResult(t *testing.T) {
	records := []struct {
		ID int `json:"id"`
	}{{ID: 101}, {ID: 102}}
	if err := validateRecordIDs(records, []int{101, 102}); err != nil {
		t.Fatal(err)
	}
	if err := validateRecordIDs(records, []int{101}); err == nil {
		t.Fatal("unexpected extra row was accepted")
	}
}
