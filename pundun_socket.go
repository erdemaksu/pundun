package pundun

import (
	"crypto/tls"
	"encoding/binary"
	"github.com/erdemaksu/scram"
	"io"
	"log"
	"net"
	"time"
)

const (
	stop = 0
)

type Session struct {
	manChan  chan int
	sendChan chan Client
	tidChan  chan uint16
}

type Client struct {
	data        []byte
	ch          chan []byte
	id          uint16
	cancelTimer chan bool
}

func Connect(host, user, pass string) (Session, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", host, conf)
	if err != nil {
		log.Println(err)
		return Session{}, err
	}

	authErr := scram.Authenticate(conn, user, pass)
	if authErr != nil {
		log.Println(authErr)
		conn.Close()
		return Session{}, authErr
	}
	log.Println("Connected to pundun node.")
	manChan := make(chan int, 1024)
	sendChan := make(chan Client, 65535)
	recvChan := make(chan []byte, 65535)

	go serverLoop(conn, manChan, sendChan, recvChan)
	go recvLoop(conn, recvChan)

	tidChan := make(chan uint16, 1)
	var tid uint16 = 0
	go tidServer(tid, tidChan)

	return Session{manChan, sendChan, tidChan}, err
}

func Disconnect(s Session) {
	defer close(s.manChan)
	s.manChan <- stop
}

func GetTid(s Session) int32 {
	tid := <-s.tidChan
	return int32(tid)
}

func SendMsg(s Session, data []byte) []byte {
	ch := make(chan []byte)
	s.sendChan <- Client{data: data, ch: ch}
	pdu := <-ch
	return pdu
}

func serverLoop(conn net.Conn, manChan chan int, sendChan chan Client, recvChan chan []byte) {
	var cid uint16 = 0
	clients := make(map[uint16]Client)
	timeout := make(chan uint16, 65535)
	defer close(sendChan)
	defer close(timeout)
	defer conn.Close()
	for {
		select {
		case msg, _ := <-manChan:
			switch msg {
			case stop:
				log.Println("Stopping server loop")
				endClients(clients)
				return
			}
		case toCid, _ := <-timeout:
			removeClient(toCid, clients, []byte{})
		case data, _ := <-recvChan:
			len := len(data)
			corrIdBytes := make([]byte, 2)
			pduBytes := make([]byte, len-2)
			copy(corrIdBytes, data[:2])
			copy(pduBytes, data[2:])
			corrId := binary.BigEndian.Uint16(corrIdBytes)
			removeClient(corrId, clients, pduBytes)
		case client, _ := <-sendChan:
			if checkCorrId(clients, cid) {
				corrId := make([]byte, 2)
				binary.BigEndian.PutUint16(corrId, cid)
				data := client.data
				len := uint32(len(data))
				wire := make([]byte, len+6)
				binary.BigEndian.PutUint32(wire, len+2)
				copy(wire[4:], corrId)
				copy(wire[6:], data)
				cancel := make(chan bool)
				client.id = cid
				client.cancelTimer = cancel
				clients[cid] = client
				conn.Write(wire)
				go expireAfter(30, cid, timeout, cancel)
				cid++
			} else {
				client.ch <- []byte{}
				close(client.ch)
			}
		}
	}
}

func checkCorrId(clients map[uint16]Client, corrId uint16) bool {
	if _, ok := clients[corrId]; ok {
		return false
	} else {
		return true
	}
}

func recvLoop(conn net.Conn, recvChan chan []byte) {
	defer close(recvChan)
	for {
		// Receive length of package
		lenBuf := make([]byte, 4)
		n, err := conn.Read(lenBuf)

		if n != 4 || err != nil {
			log.Printf("n: %v, error: %v", n, err)
			return
		} else {
			// Receive encoded pdu
			len := binary.BigEndian.Uint32(lenBuf)
			buf := make([]byte, len)
			n, err = io.ReadFull(conn, buf)
			if uint32(n) != len || err != nil {
				log.Printf("%v ?= %v || err ?= %v\n", n, len, err)
			} else {
				recvChan <- buf
			}
		}
	}
}

func tidServer(tid uint16, tidChan chan uint16) {
	for {
		tidChan <- tid
		tid++
	}
}

func expireAfter(t int, cid uint16, timeout chan uint16, cancel chan bool) {
	timer := time.NewTimer(time.Duration(t) * time.Second)
	select {
	case <-timer.C:
		select {
		case timeout <- cid:
		default:
		}
	case <-cancel:
		timer.Stop()
	}
}

func removeClient(cid uint16, clients map[uint16]Client, bytes []byte) {
	if client, exists := clients[cid]; exists {
		endClient(client, bytes)
		delete(clients, cid)
	}
}

func endClients(clients map[uint16]Client) {
	for cid, client := range clients {
		endClient(client, []byte{})
		delete(clients, cid)
	}
}

func endClient(client Client, bytes []byte) {
	defer close(client.cancelTimer)
	defer close(client.ch)
	select {
	case client.cancelTimer <- true:
	default:
		//Do nothing
	}
	client.ch <- bytes
}
