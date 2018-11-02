// Pundun package provides API for using Pundun Databases.
package pundun

import (
	"encoding/binary"
	"errors"
	//"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/pundunlabs/apollo"
	"log"
	//"reflect"
)

//Default timeout value for database procedures.
const (
	timeout = 60
)

type Tda struct {
	NumOfBuckets uint32
	TimeMargin   TimeMargin
	TsField      string
	Precision    int
}

type Wrapper struct {
	NumOfBuckets uint32
	TimeMargin   TimeMargin
	SizeMargin   SizeMargin
}

const (
	Second      = 0
	Millisecond = 1
	Microsecond = 2
	Nanosecond  = 3
)

const (
	Seconds = 0
	Minutes = 1
	Hours   = 2
)

const (
	Megabytes = 0
	Gigabytes = 1
)

type TimeMargin struct {
	Unit  int
	Value uint32
}

type SizeMargin struct {
	Unit  int
	Value uint32
}

const (
	Result = 0
	Error  = 1
)

const (
	OK = 0
)

type KVP struct {
	Key     map[string]interface{}
	Columns map[string]interface{}
}

type KVL struct {
	List         []KVP
	Continuation map[string]interface{}
}

type Iterator struct {
	Kvp KVP
	It  []byte
}

const (
	Increment = 0
	Overwrite = 1
)

const (
	Leveldb           = 0
	MemLeveldb        = 1
	LeveldbWrapped    = 2
	MemLeveldbWrapped = 3
	LeveldbTda        = 4
	MemLeveldbTda     = 5
	Rocksdb           = 6
)

const (
	VirtualNodes = 0
	Consistent   = 1
	Uniform      = 2
	Rendezvous   = 3
)

type UpdateOperation struct {
	Field        string
	Instruction  int
	Value        interface{}
	DefaultValue interface{}
	Threshold    *uint32
	SetValue     *uint32
}

type IndexConfig struct {
	Column  string
	Options IndexOptions
}

type IndexOptions struct {
	CharFilter  int
	Tokenizer   int
	TokenFilter TokenFilter
}

// CharFilter enum values for unicode normalizations.
const (
	NFC  = 0
	NFD  = 1
	NFKC = 2
	NFKD = 3
)

// Tokenizer enum values.
const (
	UNICODE_WORD_BOUNDARIES = 0
)

// TokenFilter definition, usedin IndexOptions.
type TokenFilter struct {
	Transform int
	Add       []string
	Delete    []string
	Stats     int
}

// TokenTransform enum values.
const (
	LOWERCASE = 0
	UPPERCASE = 1
	CASEFOLD  = 2
)

// TokenStats enum values.
const (
	NOSTATS   = 0
	UNIQUE    = 1
	FREQUENCY = 2
	POSITION  = 3
)

// Posting is the result og read_index procedure/
type Posting struct {
	Key       map[string]interface{}
	Timestamp uint32
	Frequency uint32
	Position  uint32
}

// Posting Filter as argument to IndexRead
type PostingFilter struct {
	SortBy      int
	StartTs     uint32
	EndTs       uint32
	MaxPostings uint32
}

// SortBy enum values.
const (
	RELEVANCE = 0
	TIMESTAMP = 1
)

func tidServe(tid, max int32, req chan string, resp chan int32) {
	for {
		select {
		case msg := <-req:
			switch msg {
			case "tid":
				resp <- tid
				if tid == max {
					tid = 0
				} else {
					tid++
				}
			case "stop":
				log.Printf("Stopping id server..\n")
				close(req)
				close(resp)
				break
			}
		}
	}
}

// Compose a AuthExchange PDU.
func ComposeAuthExchange(s Session, payload []byte) ([]byte, error) {
	authExchange := &apollo.AuthExchange{
		Payload: payload,
	}

	procedure := &apollo.ApolloPdu_AuthExchange{
		AuthExchange: authExchange,
	}

	pdu := &apollo.ApolloPdu{Procedure: procedure}
	tid := GetTid(s)
	pdu = makePdu(pdu, tid)
	pduBin, err := proto.Marshal(pdu)
	return pduBin, err
}

// De-Compose a AuthExchange PDU.
func DecomposeAuthExchange(buf []byte) ([]byte, error) {
	recvPdu := &apollo.ApolloPdu{}
	err := proto.Unmarshal(buf, recvPdu)
	if err != nil {
		log.Println("unmarshaling error: ", err)
		return nil, err
	}
	ae := recvPdu.GetAuthExchange()
	payload := ae.GetPayload()
	return payload, err
}

// Create a pundun table.
func CreateTable(s Session, tableName string, key []string, options map[string]interface{}) (interface{}, error) {
	tableOptions := fixOptions(options)

	createTable := &apollo.CreateTable{
		TableName:    *proto.String(tableName),
		Keys:         key,
		TableOptions: tableOptions,
	}

	procedure := &apollo.ApolloPdu_CreateTable{
		CreateTable: createTable,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Delete a pundun table.
func DeleteTable(s Session, tableName string) (interface{}, error) {
	deleteTable := &apollo.DeleteTable{
		TableName: *proto.String(tableName),
	}

	procedure := &apollo.ApolloPdu_DeleteTable{
		DeleteTable: deleteTable,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}
	res, err := run_transaction(s, pdu)
	return res, err
}

// Open a pundun table.
func OpenTable(s Session, tableName string) (interface{}, error) {
	openTable := &apollo.OpenTable{
		TableName: *proto.String(tableName),
	}

	procedure := &apollo.ApolloPdu_OpenTable{
		OpenTable: openTable,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Close a pundun table.
func CloseTable(s Session, tableName string) (interface{}, error) {
	closeTable := &apollo.CloseTable{
		TableName: *proto.String(tableName),
	}

	procedure := &apollo.ApolloPdu_CloseTable{
		CloseTable: closeTable,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Retrieve table information.
func TableInfo(s Session, tableName string, attrs []string) (interface{}, error) {
	attributes := fixAttributes(attrs)
	tableInfo := &apollo.TableInfo{
		TableName:  *proto.String(tableName),
		Attributes: attributes,
	}

	procedure := &apollo.ApolloPdu_TableInfo{
		TableInfo: tableInfo,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Read a key from pundun table.
func Read(s Session, tableName string, key map[string]interface{}) (interface{}, error) {
	keyFields := fixFields(key)
	read := &apollo.Read{
		TableName: *proto.String(tableName),
		Key:       keyFields,
	}

	procedure := &apollo.ApolloPdu_Read{
		Read: read,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Write key and columns to a pundun table.
func Write(s Session, tableName string, key, columns map[string]interface{}) (interface{}, error) {
	keyFields := fixFields(key)
	columnFields := fixFields(columns)
	write := &apollo.Write{
		TableName: *proto.String(tableName),
		Key:       keyFields,
		Columns:   columnFields,
	}

	procedure := &apollo.ApolloPdu_Write{
		Write: write,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Update a key's columns on a pundun table.
func Update(s Session, tableName string, key map[string]interface{}, upOps []UpdateOperation) (interface{}, error) {
	keyFields := fixFields(key)
	updateOperations := fixUpdateOperations(upOps)
	update := &apollo.Update{
		TableName:       *proto.String(tableName),
		Key:             keyFields,
		UpdateOperation: updateOperations,
	}

	procedure := &apollo.ApolloPdu_Update{
		Update: update,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Delete a key from pundun table.
func Delete(s Session, tableName string, key map[string]interface{}) (interface{}, error) {
	keyFields := fixFields(key)
	delete := &apollo.Delete{
		TableName: *proto.String(tableName),
		Key:       keyFields,
	}

	procedure := &apollo.ApolloPdu_Delete{
		Delete: delete,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Read a range of keys from pundun table.
// Limit the amount of keys read by limit arg.
func ReadRange(s Session, tableName string, skey, ekey map[string]interface{}, limit int) (interface{}, error) {
	skeyFields := fixFields(skey)
	ekeyFields := fixFields(ekey)
	readRange := &apollo.ReadRange{
		TableName: *proto.String(tableName),
		StartKey:  skeyFields,
		EndKey:    ekeyFields,
		Limit:     *proto.Uint32(uint32(limit)),
	}

	procedure := &apollo.ApolloPdu_ReadRange{
		ReadRange: readRange,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Read a range of N number of Keys starting from a key.
func ReadRangeN(s Session, tableName string, skey map[string]interface{}, n int) (interface{}, error) {
	skeyFields := fixFields(skey)
	readRangeN := &apollo.ReadRangeN{
		TableName: *proto.String(tableName),
		StartKey:  skeyFields,
		N:         *proto.Uint32(uint32(n)),
	}

	procedure := &apollo.ApolloPdu_ReadRangeN{
		ReadRangeN: readRangeN,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Read the first key on a pundun table and get an iterator.
func First(s Session, tableName string) (interface{}, error) {
	first := &apollo.First{
		TableName: *proto.String(tableName),
	}

	procedure := &apollo.ApolloPdu_First{
		First: first,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Read the last key on a pundun table and get an iterator.
func Last(s Session, tableName string) (interface{}, error) {
	last := &apollo.Last{
		TableName: *proto.String(tableName),
	}

	procedure := &apollo.ApolloPdu_Last{
		Last: last,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Seek a key on pundun table ang get an iterator.
func Seek(s Session, tableName string, key map[string]interface{}) (interface{}, error) {
	keyFields := fixFields(key)
	seek := &apollo.Seek{
		TableName: *proto.String(tableName),
		Key:       keyFields,
	}

	procedure := &apollo.ApolloPdu_Seek{
		Seek: seek,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Get the next key after the position of given iterator.
func Next(s Session, it []byte) (interface{}, error) {
	next := &apollo.Next{
		It: it,
	}

	procedure := &apollo.ApolloPdu_Next{
		Next: next,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Get the previous key before the position of given iterator.
func Prev(s Session, it []byte) (interface{}, error) {
	prev := &apollo.Prev{
		It: it,
	}

	procedure := &apollo.ApolloPdu_Prev{
		Prev: prev,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Make the given column(s) indexed on pundun table.
func AddIndex(s Session, tableName string, configList []IndexConfig) (interface{}, error) {
	indexConfig := fixIndexConfigList(configList)

	addIndex := &apollo.AddIndex{
		TableName: *proto.String(tableName),
		Config:    indexConfig,
	}

	procedure := &apollo.ApolloPdu_AddIndex{
		AddIndex: addIndex,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Stop indexing column(s) on a pundun table and
// remove previously indexed terms on those columns.
func RemoveIndex(s Session, tableName string,
	columns []string) (interface{}, error) {

	removeIndex := &apollo.RemoveIndex{
		TableName: *proto.String(tableName),
		Columns:   columns,
	}

	procedure := &apollo.ApolloPdu_RemoveIndex{
		RemoveIndex: removeIndex,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// Get the keys by terms that are indexed on given pundun table and it's column.
func IndexRead(s Session, tableName string, columnName string, term string, pf PostingFilter) (interface{}, error) {
	var postingFilter *apollo.PostingFilter
	postingFilter = fixPostingFilter(pf)
	indexRead := &apollo.IndexRead{
		TableName:  *proto.String(tableName),
		ColumnName: *proto.String(columnName),
		Term:       *proto.String(term),
		Filter:     postingFilter,
	}
	procedure := &apollo.ApolloPdu_IndexRead{
		IndexRead: indexRead,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

// List the existing tables on Pundun
func ListTables(s Session) (interface{}, error) {
	listTables := &apollo.ListTables{}
	procedure := &apollo.ApolloPdu_ListTables{
		ListTables: listTables,
	}

	pdu := &apollo.ApolloPdu{
		Procedure: procedure,
	}

	res, err := run_transaction(s, pdu)
	return res, err
}

func run_transaction(s Session, pdu *apollo.ApolloPdu) (interface{}, error) {
	tid := GetTid(s)
	pdu = makePdu(pdu, tid)
	pduBin, err := proto.Marshal(pdu)
	if err != nil {
		log.Println("marshaling error: ", err)
		return nil, err
	}

	recv, err := send(s, pduBin)

	if err != nil {
		log.Println("error: ", err)
	}
	res, err := waitForResponse(recv)
	return res, err
}

func makePdu(pdu *apollo.ApolloPdu, tid uint32) *apollo.ApolloPdu {
	version := &apollo.Version{
		Major: *proto.Uint32(0),
		Minor: *proto.Uint32(1),
	}
	pdu.Version = version
	pdu.TransactionId = *proto.Uint32(tid)
	return pdu
}

func send(s Session, data []byte) ([]byte, error) {
	response := SendMsg(s, data)
	return response, nil
}

func waitForResponse(recv []byte) (interface{}, error) {
	recvPdu := &apollo.ApolloPdu{}
	err := proto.Unmarshal(recv, recvPdu)

	if err != nil {
		log.Println("unmarshaling error: ", err)
		return nil, err
	}

	e := recvPdu.GetError()
	r := recvPdu.GetResponse()
	if r != nil {
		result := getResult(r)
		return result, err
	}
	if e != nil {
		pErr := getError(e)
		return pErr, err
	}
	return nil, errors.New("invalid response")
}

func getResult(r *apollo.Response) interface{} {
	ok := r.GetOk()
	if ok != "" {
		return OK
	}
	c := r.GetColumns()
	if c != nil {
		return formatColumns(c)
	}
	kcp := r.GetKeyColumnsPair()
	if kcp != nil {
		return formatKcp(kcp)
	}
	kcl := r.GetKeyColumnsList()
	if kcl != nil {
		return formatKcl(kcl)
	}
	pl := r.GetProplist()
	if pl != nil {
		return formatColumns(pl)
	}
	po := r.GetPostings()
	if po != nil {
		return formatPostings(po)
	}
	it := r.GetKcpIt()
	if it != nil {
		return formatKcpIt(it)
	}
	strList := r.GetStringList()
	if strList != nil {
		return formatStringList(strList)
	} else {
		return nil
	}
}

func getError(e *apollo.Error) map[string]string {
	m := make(map[string]string)
	t := e.GetTransport()
	if t != "" {
		m["transport"] = t
	}
	p := e.GetProtocol()
	if p != "" {
		m["protocol"] = p
	}
	s := e.GetSystem()
	if s != "" {
		m["system"] = s
	}
	o := e.GetMisc()
	if o != "" {
		m["misc"] = o
	}
	return m
}

func formatColumns(c *apollo.Fields) map[string]interface{} {
	fields := c.GetFields()
	return formatFields(fields)
}

func formatPostings(c *apollo.Postings) []Posting {
	list := c.GetList()
	postings := make([]Posting, len(list))
	for i := range list {
		postings[i] = formatPosting(list[i])
	}
	return postings
}

func formatPosting(p *apollo.Posting) Posting {
	keyFields := p.GetKey()
	keyMap := formatFields(keyFields)
	timestamp := p.GetTimestamp()
	frequency := p.GetFrequency()
	position := p.GetPosition()
	return Posting{keyMap, timestamp, frequency, position}
}

func formatKcp(kcp *apollo.KeyColumnsPair) KVP {
	keyFields := kcp.GetKey()
	columnFields := kcp.GetColumns()
	keyMap := formatFields(keyFields)
	columnsMap := formatFields(columnFields)
	return KVP{keyMap, columnsMap}
}

func formatKcpIt(kcpIt *apollo.KcpIt) Iterator {
	kvp := kcpIt.GetKeyColumnsPair()
	it := kcpIt.It
	return Iterator{formatKcp(kvp), it}
}

func formatStringList(strList *apollo.FieldNames) []string {
	return strList.FieldNames
}

func formatKcl(kcl *apollo.KeyColumnsList) KVL {
	protoList := kcl.GetList()
	list := make([]KVP, len(protoList))
	for i := range protoList {
		list[i] = formatKcp(protoList[i])
	}
	cont := kcl.GetContinuation()
	contKey := cont.GetKey()
	return KVL{list, formatFields(contKey)}
}

func formatFields(fields []*apollo.Field) map[string]interface{} {
	m := make(map[string]interface{})
	for i := range fields {
		f := fields[i]
		m[f.Name] = formatValue(f.Value)
	}
	return m
}

func formatValue(v *apollo.Value) interface{} {
	var value interface{}
	switch v.GetType().(type) {
	case *apollo.Value_String_:
		value = v.GetString_()
	case *apollo.Value_Binary:
		value = v.GetBinary()
	case *apollo.Value_Int:
		value = int64(v.GetInt())
	case *apollo.Value_Double:
		value = v.GetDouble()
	case *apollo.Value_Boolean:
		value = v.GetBoolean()
	case *apollo.Value_Null:
		value = v.GetNull()
	case *apollo.Value_List:
		list := v.GetList().Values
		l := make([]interface{}, len(list))
		for i, v := range list {
			l[i] = formatValue(v)
		}
		value = l
	case *apollo.Value_Map:
		mmap := v.GetMap().Values
		m := make(map[string]interface{})
		for k, v := range mmap {
			m[k] = formatValue(v)
		}
		value = m
	}
	return value
}

func fixOptions(options map[string]interface{}) []*apollo.TableOption {
	tableOptions := make([]*apollo.TableOption, 0)
	for k, v := range options {
		tableOptions = fixOption(k, v, tableOptions)
	}
	return tableOptions
}

func fixOption(k string, v interface{}, opts []*apollo.TableOption) []*apollo.TableOption {
	var opt *apollo.TableOption

	switch k {
	case "type":
		tableType := apollo.Type_ROCKSDB
		switch v {
		case Leveldb:
			tableType = apollo.Type_LEVELDB
		case MemLeveldb:
			tableType = apollo.Type_MEMLEVELDB
		case LeveldbWrapped:
			tableType = apollo.Type_LEVELDBWRAPPED
		case MemLeveldbWrapped:
			tableType = apollo.Type_MEMLEVELDBWRAPPED
		case LeveldbTda:
			tableType = apollo.Type_LEVELDBTDA
		case MemLeveldbTda:
			tableType = apollo.Type_MEMLEVELDBTDA
		default:
		}
		opt = &apollo.TableOption{Opt: &apollo.TableOption_Type{tableType}}
	case "data_model":
		dataModel := apollo.DataModel_ARRAY
		switch v {
		case "kv":
			dataModel = apollo.DataModel_KV
		case "map":
			dataModel = apollo.DataModel_MAP
		default:
		}
		opt = &apollo.TableOption{Opt: &apollo.TableOption_DataModel{dataModel}}
	case "wrapper":
		wrapper := fixWrapper(v.(Wrapper))
		opt = &apollo.TableOption{Opt: &apollo.TableOption_Wrapper{wrapper}}
	case "tda":
		tda := fixTda(v.(Tda))
		opt = &apollo.TableOption{Opt: &apollo.TableOption_Tda{tda}}
	case "hashing_method":
		hm := apollo.HashingMethod_UNIFORM
		switch v {
		case VirtualNodes:
			hm = apollo.HashingMethod_VIRTUALNODES
		case Consistent:
			hm = apollo.HashingMethod_CONSISTENT
		case Uniform:
			hm = apollo.HashingMethod_UNIFORM
		case Rendezvous:
			hm = apollo.HashingMethod_RENDEZVOUS
		default:
		}
		opt = &apollo.TableOption{Opt: &apollo.TableOption_HashingMethod{hm}}
	default:
	}
	if opt != nil {
		len := len(opts) + 1
		newOpts := make([]*apollo.TableOption, len)
		copy(newOpts, opts[:])
		newOpts[len-1] = opt
		return newOpts
	} else {
		return opts
	}
}

func fixTda(t Tda) *apollo.Tda {
	tm := &t.TimeMargin
	tda := apollo.Tda{
		NumOfBuckets: t.NumOfBuckets,
		TsField:      t.TsField,
	}
	fixTdaMargin(&tda, tm)
	fixPrecision(&tda, t.Precision)
	return &tda
}

func fixPrecision(tda *apollo.Tda, p int) {
	precision := apollo.TimeUnit_SECOND
	switch p {
	case Millisecond:
		precision = apollo.TimeUnit_MILLISECOND
	case Microsecond:
		precision = apollo.TimeUnit_MICROSECOND
	case Nanosecond:
		precision = apollo.TimeUnit_NANOSECOND
	default:
	}
	tda.Precision = precision
}

func fixTdaMargin(tda *apollo.Tda, tm *TimeMargin) {
	if tm != nil {
		timeUnit := tm.Unit
		t := tm.Value
		switch timeUnit {
		case Seconds:
			tda.TimeMargin = &apollo.Tda_Seconds{*proto.Uint32(t)}
		case Minutes:
			tda.TimeMargin = &apollo.Tda_Minutes{*proto.Uint32(t)}
		case Hours:
			tda.TimeMargin = &apollo.Tda_Hours{*proto.Uint32(t)}
		}
	}
}

func fixWrapper(w Wrapper) *apollo.Wrapper {
	tm := &w.TimeMargin
	sm := &w.SizeMargin
	wrapper := apollo.Wrapper{
		NumOfBuckets: w.NumOfBuckets,
	}
	fixTimeMargin(&wrapper, tm)
	fixSizeMargin(&wrapper, sm)

	return &wrapper
}

func fixTimeMargin(w *apollo.Wrapper, tm *TimeMargin) {
	if tm != nil {
		timeUnit := tm.Unit
		t := tm.Value
		switch timeUnit {
		case Seconds:
			w.TimeMargin = &apollo.Wrapper_Seconds{*proto.Uint32(t)}
		case Minutes:
			w.TimeMargin = &apollo.Wrapper_Minutes{*proto.Uint32(t)}
		case Hours:
			w.TimeMargin = &apollo.Wrapper_Hours{*proto.Uint32(t)}
		}
	}
}

func fixSizeMargin(w *apollo.Wrapper, sm *SizeMargin) {
	if sm != nil {
		sizeUnit := sm.Unit
		s := sm.Value
		switch sizeUnit {
		case Megabytes:
			w.SizeMargin = &apollo.Wrapper_Megabytes{*proto.Uint32(s)}
		case Gigabytes:
			w.SizeMargin = &apollo.Wrapper_Gigabytes{*proto.Uint32(s)}
		}
	}
}

func fixAttributes(attrs []string) []string {
	ps := make([]string, len(attrs))
	for a := range attrs {
		ps[a] = *proto.String(attrs[a])
	}
	return ps
}

func fixFields(m map[string]interface{}) []*apollo.Field {
	fields := make([]*apollo.Field, 0)
	for k, v := range m {
		fields = fixField(k, v, fields)
	}
	return fields
}

func fixField(k string, v interface{}, fields []*apollo.Field) []*apollo.Field {
	var field *apollo.Field
	value := fixValue(v)
	field = &apollo.Field{Name: *proto.String(k),
		Value: value}
	len := len(fields) + 1
	newFields := make([]*apollo.Field, len)
	copy(newFields, fields[:])
	newFields[len-1] = field
	return newFields
}

func fixValue(v interface{}) *apollo.Value {
	var value *apollo.Value
	switch v.(type) {
	case string:
		value = &apollo.Value{
			Type: &apollo.Value_String_{*proto.String(v.(string))},
		}
	case []byte:
		value = &apollo.Value{
			Type: &apollo.Value_Binary{v.([]byte)},
		}
	case int:
		value = &apollo.Value{
			Type: &apollo.Value_Int{*proto.Int64(int64(v.(int)))},
		}
	case int8:
		value = &apollo.Value{
			Type: &apollo.Value_Int{*proto.Int64(int64(v.(int8)))},
		}
	case int16:
		value = &apollo.Value{
			Type: &apollo.Value_Int{*proto.Int64(int64(v.(int16)))},
		}
	case int32:
		value = &apollo.Value{
			Type: &apollo.Value_Int{*proto.Int64(int64(v.(int32)))},
		}
	case int64:
		value = &apollo.Value{
			Type: &apollo.Value_Int{*proto.Int64(v.(int64))},
		}
	case float64:
		value = &apollo.Value{
			Type: &apollo.Value_Double{*proto.Float64(v.(float64))},
		}
	case bool:
		value = &apollo.Value{
			Type: &apollo.Value_Boolean{*proto.Bool(v.(bool))},
		}
	case []interface{}:
		values := make([]*apollo.Value, len(v.([]interface{})))
		for i, e := range v.([]interface{}) {
			values[i] = fixValue(e)
		}
		value = &apollo.Value{
			Type: &apollo.Value_List{
				&apollo.ListValue{Values: values},
			},
		}
	case map[string]interface{}:
		values := make(map[string]*apollo.Value)
		for k, e := range v.(map[string]interface{}) {
			values[k] = fixValue(e)
		}
		value = &apollo.Value{
			Type: &apollo.Value_Map{
				&apollo.MapValue{Values: values},
			},
		}
	default:
		//fmt.Println("default: ", reflect.TypeOf(v))
		if v == nil {
			value = &apollo.Value{
				Type: &apollo.Value_Null{
					[]byte{},
				},
			}
		}
	}
	return value
}

func fixUpdateOperations(upOps []UpdateOperation) []*apollo.UpdateOperation {
	updateOperations := make([]*apollo.UpdateOperation, 0)
	for i := range upOps {
		updateOperations = fixUpdateOperation(upOps[i], updateOperations)
	}
	return updateOperations
}

func fixUpdateOperation(upOp UpdateOperation, updateOperations []*apollo.UpdateOperation) []*apollo.UpdateOperation {
	i := upOp.Instruction
	instruction := apollo.UpdateInstruction_INCREMENT
	switch i {
	case Overwrite:
		instruction = apollo.UpdateInstruction_OVERWRITE
	default:
	}
	var updateInstruction *apollo.UpdateInstruction
	threshold := encodeInt32(upOp.Threshold)
	setvalue := encodeInt32(upOp.SetValue)
	updateInstruction = &apollo.UpdateInstruction{
		Instruction: instruction,
		Threshold:   threshold,
		SetValue:    setvalue}

	value := fixValue(upOp.Value)
	defaultValue := fixDefaultValue(upOp.DefaultValue)

	var updateOperation *apollo.UpdateOperation
	updateOperation = &apollo.UpdateOperation{
		Field:             *proto.String(upOp.Field),
		UpdateInstruction: updateInstruction,
		Value:             value,
		DefaultValue:      defaultValue}

	len := len(updateOperations) + 1
	newUpdateOperations := make([]*apollo.UpdateOperation, len)
	copy(newUpdateOperations, updateOperations[:])
	newUpdateOperations[len-1] = updateOperation
	return newUpdateOperations
}

func fixDefaultValue(v interface{}) *apollo.Value {
	if v == nil {
		return nil
	} else {
		return fixValue(v)
	}
}

func encodeInt32(v *uint32) []byte {
	if v != nil {
		bytes := make([]byte, 4)
		binary.BigEndian.PutUint32(bytes, *v)
		return bytes
	} else {
		return make([]byte, 0)
	}
}

func fixIndexConfigList(configList []IndexConfig) []*apollo.IndexConfig {
	indexConfig := make([]*apollo.IndexConfig, 0)
	for c := range configList {
		indexConfig = fixIndexConfig(configList[c], indexConfig)
	}
	return indexConfig
}

func fixIndexConfig(c IndexConfig, indexConfig []*apollo.IndexConfig) []*apollo.IndexConfig {
	column := c.Column
	options := fixIndexOptions(c.Options)
	var config = &apollo.IndexConfig{
		Column:  column,
		Options: options,
	}
	if config != nil {
		len := len(indexConfig) + 1
		newIndexConfig := make([]*apollo.IndexConfig, len)
		copy(newIndexConfig, indexConfig[:])
		newIndexConfig[len-1] = config
		return newIndexConfig
	} else {
		return indexConfig
	}
}

func fixPostingFilter(pf PostingFilter) *apollo.PostingFilter {
	sortBy := apollo.SortBy_RELEVANCE
	switch pf.SortBy {
	case TIMESTAMP:
		sortBy = apollo.SortBy_TIMESTAMP
	default:
	}

	startTs := setTs(pf.StartTs)
	endTs := setTs(pf.EndTs)
	maxPostings := pf.MaxPostings
	postingFilter := &apollo.PostingFilter{
		SortBy:      sortBy,
		StartTs:     startTs,
		EndTs:       endTs,
		MaxPostings: maxPostings,
	}
	return postingFilter
}

func fixIndexOptions(opts IndexOptions) *apollo.IndexOptions {
	charFilter := apollo.CharFilter_NFC
	switch opts.CharFilter {
	case NFD:
		charFilter = apollo.CharFilter_NFD
	case NFKC:
		charFilter = apollo.CharFilter_NFKC
	case NFKD:
		charFilter = apollo.CharFilter_NFKD
	default:
	}

	tokenizer := apollo.Tokenizer_UNICODE_WORD_BOUNDARIES

	filter := opts.TokenFilter
	transform := apollo.TokenTransform_LOWERCASE
	switch filter.Transform {
	case UPPERCASE:
		transform = apollo.TokenTransform_UPPERCASE
	case CASEFOLD:
		transform = apollo.TokenTransform_CASEFOLD
	default:
	}
	add := filter.Add
	delete := filter.Delete

	stats := apollo.TokenStats_NOSTATS
	switch filter.Stats {
	case UNIQUE:
		stats = apollo.TokenStats_UNIQUE
	case FREQUENCY:
		stats = apollo.TokenStats_FREQUENCY
	case POSITION:
		stats = apollo.TokenStats_POSITION
	default:
	}

	tokenFilter := &apollo.TokenFilter{
		Transform: transform,
		Add:       add,
		Delete:    delete,
		Stats:     stats,
	}

	indexOptions := &apollo.IndexOptions{
		CharFilter:  charFilter,
		Tokenizer:   tokenizer,
		TokenFilter: tokenFilter,
	}
	return indexOptions
}

func setTs(ts uint32) []byte {
	if ts > 0 {
		binTs := make([]byte, 4)
		binary.BigEndian.PutUint32(binTs, ts)
		return binTs
	} else {
		binTs := make([]byte, 0)
		return binTs
	}
}
