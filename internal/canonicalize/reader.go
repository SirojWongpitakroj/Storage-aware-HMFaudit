package canonicalize

import (
	"bufio"
	"fmt"
	"os"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
)

type DatasetReader struct {
	Reader  *bufio.Scanner
	CurrLog *domain.Log
	file    *os.File
}

func NewDatasetReader() (*DatasetReader, error) {
	file, err := os.Open("../../../dataset/combined/openstack_uniform_combined.jsonl")
	if err != nil {
		return nil, fmt.Errorf("error opening a log source")
	}

	scanner := DatasetReader{CurrLog: &domain.Log{}}
	scanner.file = file
	scanner.Reader = bufio.NewScanner(file)

	return &scanner, nil
}

func (r *DatasetReader) Next() bool {
	if r.Reader.Scan() {
		logBytes := r.Reader.Bytes()

		r.parse(logBytes)

		//add logical attr to AD
		r.CurrLog.AD = domain.EncodeAD(r.CurrLog)

		r.encrypt(logBytes)
	} else {
		r.file.Close()
		if err := r.Reader.Err(); err != nil {
			panic(err)
		}
		return false
	}
	return true
}

func (r *DatasetReader) Record() *domain.Log {
	return r.CurrLog
}
