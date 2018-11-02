package pundun

import (
	"log"
	"testing"
	"time"
)

func TestRun1(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	session, err := Connect("127.0.0.1:8887", "admin", "admin")
	if err != nil {
		log.Println(err)
		return
	}
	defer Disconnect(session)

	tableName := "ct"
	keyDef := []string{"imsi", "ts"}
	options := map[string]interface{}{
		"type":               Rocksdb,
		"data_model":         "array",
		"comparator":         "descending",
		"time_series":        false,
		"num_of_shards":      8,
		"distributed":        true,
		"replication_factor": 1,
		"hash_exclude":       []string{"ts"},
	}

	log.Println("List Tables")
	res, err := ListTables(session)
	log.Printf("Result: %v\n", res)

	if stringInSlice(tableName, res.([]string)) == true {
		log.Println("Delete Table")
		res, err = DeleteTable(session, tableName)
		log.Printf("Delete Table result: %v\n", res)
	}
	log.Printf("Create Table: %v\n", tableName)
	res, err = CreateTable(session, tableName, keyDef, options)
	log.Printf("Result: %v\n", res)

	log.Println("Table Info")
	res, err = TableInfo(session, tableName, []string{"type", "key"})
	log.Printf("Result: %v\n", res)

	log.Println("Close Table")
	res, err = CloseTable(session, tableName)
	log.Printf("Result: %v\n", res)

	log.Println("Open Table")
	res, err = OpenTable(session, tableName)
	log.Printf("Result: %v\n", res)

	time_ := time.Now()
	ts, _ := time_.MarshalBinary()
	key := map[string]interface{}{
		"imsi": "123456789012345",
		"ts":   ts,
	}

	var exampleList []interface{}
	exampleList = append(exampleList, 1)
	exampleList = append(exampleList, "some text")
	exampleList = append(exampleList, 99.9)
	exampleList = append(exampleList, false)
	exampleList = append(exampleList, key)

	exampleMap := map[string]interface{}{
		"inner_list": exampleList,
		"inner_map":  key,
		"scalar":     63452,
	}

	columns := map[string]interface{}{
		"name":    "John",
		"counter": 1,
		"bin":     []byte{0, 0, 0, 1},
		"bool":    true,
		"double":  5.5,
		"list":    exampleList,
		"map":     exampleMap,
	}
	var threshold uint32 = 2
	var setvalue uint32 = 1
	upOp := []UpdateOperation{
		UpdateOperation{
			Field:        "new_counter_1",
			Instruction:  Increment,
			Value:        1,
			DefaultValue: 0,
			Threshold:    &threshold,
			SetValue:     &setvalue},
		UpdateOperation{
			Field:       "new_counter_2",
			Instruction: Increment,
			Value:       1,
			Threshold:   &threshold,
			SetValue:    &setvalue},
		UpdateOperation{
			Field:       "counter",
			Instruction: Increment,
			Value:       1},
	}

	log.Println("Write")
	res, err = Write(session, tableName, key, columns)
	log.Printf("Write result: %v\n", res)

	log.Println("Update")
	res, err = Update(session, tableName, key, upOp)
	log.Printf("Update result: %v\n", res)

	log.Println("Read")
	res, err = Read(session, tableName, key)
	log.Printf("Read result: %v\n", res)

	stime_ := time.Now()
	sts, _ := stime_.MarshalBinary()
	skey := map[string]interface{}{
		"imsi": "123456789012345",
		"ts":   sts,
	}

	log.Println("Read Range")
	res, err = ReadRange(session, tableName, skey, key, 100)
	log.Printf("Read Range result: %v\n", res)

	log.Println("Read Range N")
	res, err = ReadRangeN(session, tableName, skey, 2)
	log.Printf("Read Range N result: %v\n", res)

	log.Println("First")
	res, err = First(session, tableName)
	log.Printf("First result: %v\n", res)

	log.Println("Last")
	res, err = Last(session, tableName)
	log.Printf("Last result: %v\n", res)

	log.Println("Seek")
	res, err = Seek(session, tableName, key)
	log.Printf("Seek result: %v\n", res)

	log.Println("Delete")
	res, err = Delete(session, tableName, key)
	log.Printf("Delete result: %v\n", res)

	log.Println("Delete non existing")
	res, err = Delete(session, "nonexistingtable", key)
	log.Printf("Delete non-existing Table result: %v\n", res)

	log.Printf("Delete Table: %v\n", tableName)
	res, err = DeleteTable(session, tableName)
	log.Printf("Delete Table result: %v\n", res)
}

func TestRun2(t *testing.T) {
	log.Println("Testing Concurrent Operations..")
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	session, err := Connect("127.0.0.1:8887", "admin", "admin")
	defer Disconnect(session)
	if err != nil {
		log.Println(err)
		return
	}

	tableName := "ctt"
	keyDef := []string{"ts"}
	options := map[string]interface{}{
		"type":               Rocksdb,
		"data_model":         "array",
		"comparator":         "descending",
		"time_series":        false,
		"num_of_shards":      8,
		"distributed":        true,
		"replication_factor": 1,
		"hash_exclude":       []string{"ts"},
	}

	log.Printf("Create Table: %v\n", tableName)
	res, err := CreateTable(session, tableName, keyDef, options)
	log.Printf("Create Table result: %v\n", res)

	max := 65535
	log.Printf("Start %v concurrent read/write routines\n", max)
	reduce := make(chan bool, 1024)
	defer close(reduce)
	i := 0
	fail := 0

	for i < max {
		go writeRead(session, tableName, reduce)
		i++
	}
	for i > 0 {
		select {
		case b := <-reduce:
			if b == false {
				fail++
			}
			i--
		}
	}
	log.Printf("All routines (%v) returned. Failed: %v\n", max, fail)
	log.Printf("Delete Table: %v\n", tableName)
	res, err = DeleteTable(session, tableName)
	log.Printf("Delete Table Result: %v\n", res)
}

func TestRun3(t *testing.T) {
	log.Println("Testing Rocksdb, ttl and indexing..")
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	session, err := Connect("127.0.0.1:8887", "admin", "admin")
	defer Disconnect(session)
	if err != nil {
		log.Println(err)
		return
	}

	tableName := "rocksdb_ttl_index_test"
	keyDef := []string{"id"}
	options := map[string]interface{}{
		"type":               Rocksdb,
		"ttl":                60,
		"data_model":         "array",
		"comparator":         "descending",
		"time_series":        false,
		"num_of_shards":      8,
		"distributed":        true,
		"replication_factor": 1,
	}

	log.Printf("Create Table: %v\n", tableName)
	res, err := CreateTable(session, tableName, keyDef, options)
	log.Printf("Create Table result: %v\n", res)

	john_key := map[string]interface{}{
		"id": "1",
	}
	john_columns := map[string]interface{}{
		"name": "John",
		"text": "John the Apostle (Aramaic: ܝܘܚܢܢ ܫܠܝܚܐ‎‎ Yohanan Shliha; Hebrew: יוחנן בן זבדי‎‎ Yohanan ben Zavdi; Koine Greek: Ἰωάννης; Latin: Ioannes; c. AD 6-100) was one of the Twelve Apostles of Jesus according to the New Testament, which refers to him as Ἰωάννης. He was the son of Zebedee and Salome. His brother was James, who was another of the Twelve Apostles. Christian tradition holds that he outlived the remaining apostles and that he was the only one to die of natural causes: Judas Iscariot died by suicide, while the other ten all are considered to have died a martyr's death. This is because the Church Fathers considered him the same person as John the Evangelist, John of Patmos, John the Elder and the Beloved Disciple, although modern theologians and scholars have not formed a consensus on the relative identities of these men. The traditions of most Christian denominations have held that John the Apostle is the author of several books of the New Testament.",
	}
	kazuo_key := map[string]interface{}{
		"id": "2",
	}
	kazuo_columns := map[string]interface{}{
		"name": "Kazuo",
		"text": "Kazuo Ishiguro OBE FRSA FRSL (石黒 一雄; born 8 November 1954) is a Nobel Prize winning British novelist, screenwriter and short story writer. He was born in Nagasaki, Japan; his family moved to England in 1960 when he was five. Ishiguro graduated from the University of Kent with a bachelor's degree in English and Philosophy in 1978 and gained his master's from the University of East Anglia's creative writing course in 1980.",
	}

	tokenFilterName := TokenFilter{
		Transform: LOWERCASE,
		Add:       []string{"john ian jon"},
		Delete:    []string{},
		Stats:     FREQUENCY}

	tokenFilterText := TokenFilter{
		Transform: CASEFOLD,
		Add:       []string{""},
		Delete:    []string{"$english_stopwords"},
		Stats:     POSITION}

	indexOptionsName := IndexOptions{
		CharFilter:  NFC,
		Tokenizer:   UNICODE_WORD_BOUNDARIES,
		TokenFilter: tokenFilterName,
	}

	indexOptionsText := IndexOptions{
		CharFilter:  NFC,
		Tokenizer:   UNICODE_WORD_BOUNDARIES,
		TokenFilter: tokenFilterText,
	}

	indexConfigList := []IndexConfig{
		IndexConfig{
			Column:  "name",
			Options: indexOptionsName,
		},
		IndexConfig{
			Column:  "text",
			Options: indexOptionsText,
		},
	}

	log.Println("Add Index")
	res, err = AddIndex(session, tableName, indexConfigList)
	log.Printf("Add Index: %v\n", res)

	log.Println("Write")
	res, err = Write(session, tableName, john_key, john_columns)
	res, err = Write(session, tableName, kazuo_key, kazuo_columns)
	log.Printf("Write result: %v\n", res)

	log.Println("Read")
	res, err = Read(session, tableName, john_key)
	log.Printf("Read result: %v\n", res)
	res, err = Read(session, tableName, kazuo_key)
	log.Printf("Read result: %v\n", res)

	log.Println("Index Read")
	var postingFilter = PostingFilter{}
	res, err = IndexRead(session, tableName, "name", "john", postingFilter)
	log.Printf("Index Read result [name:john]: %v\n", res)
	res, err = IndexRead(session, tableName, "name", "ian", postingFilter)
	log.Printf("Index Read result [name:ian]: %v\n", res)

	res, err = IndexRead(session, tableName, "text", "nagasaki", postingFilter)
	log.Printf("Index Read result [text:nagasaki]: %v\n", res)

	res, err = IndexRead(session, tableName, "text", "the", postingFilter)
	log.Printf("Index Read result [text:the]: %v\n", res)

	phr1 := "Nobel Prize winning British novelist"
	res, err = IndexRead(session, tableName, "text", phr1, postingFilter)
	log.Printf("Index Read result [text:%v]: %v\n", phr1, res)

	phr2 := "Nobel Prize winning Japanese novelist"
	res, err = IndexRead(session, tableName, "text", phr2, postingFilter)
	log.Printf("Index Read result [text:%v]: %v\n", phr2, res)

	log.Printf("Delete Table: %v\n", tableName)
	res, err = DeleteTable(session, tableName)
	log.Printf("Delete Table Result: %v\n", res)
}

func writeRead(s Session, tableName string, reduce chan bool) {
	ts := time.Now().UnixNano()
	key := map[string]interface{}{
		"ts": ts,
	}
	columns := map[string]interface{}{
		"timestamp": ts,
		"binary":    make([]byte, 4096),
	}

	_, err := Write(s, tableName, key, columns)
	if err != nil {
		reduce <- false
		return
	}

	res, err := Read(s, tableName, key)
	if err != nil {
		reduce <- false
		return
	}

	switch res.(type) {
	case map[string]interface{}:
		cols := res.(map[string]interface{})
		resTs := cols["timestamp"].(int64)
		if resTs == ts {
			reduce <- true
			return
		} else {
			reduce <- false
			return
		}
	default:
		reduce <- false
	}
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
