package pundun

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"github.com/pundunlabs/go-scram"
	"io"
	"log"
	"net"
	"strings"
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

func HSend(conn net.Conn, s Session, payload []byte) (int, error) {
	pduBin, err := ComposeAuthExchange(s, payload)
	if err != nil {
		return 1, err
	}
	len := uint32(len(pduBin)) + 2
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, len)
	corrid := make([]byte, 2)
	binary.BigEndian.PutUint16(corrid, 0)
	conn.Write(header)
	conn.Write(corrid)
	return conn.Write(pduBin)
}

func HRead(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	n, herr := conn.Read(lenBuf)

	if n != 4 {
		return nil, errors.New("could not read packet header")
	}

	if herr != nil {
		return nil, herr
	}

	len := binary.BigEndian.Uint32(lenBuf)
	buf := make([]byte, len)
	_, derr := io.ReadFull(conn, buf)
	if derr != nil {
		return nil, derr
	}
	payload, dcerr := DecomposeAuthExchange(buf[2:])
	if dcerr != nil {
		return nil, dcerr
	}
	return payload, nil
}

type Client struct {
	data        []byte
	ch          chan []byte
	id          uint16
	cancelTimer chan bool
}

func Connect(host string, user string, pass string) (Session, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", host, conf)
	if err != nil {
		log.Println(err)
		return Session{}, err
	}

	tidChan := make(chan uint16, 1)
	var tid uint16 = 0
	go tidServer(tid, tidChan)
	session := Session{tidChan: tidChan}

	scramc := struct{ scram.ScramConn }{}
	scramc.Send = func(data []byte) (int, error) {
		return HSend(conn, session, data)
	}
	scramc.Read = func() ([]byte, error) { return HRead(conn) }
	authErr := scram.Authenticate(scramc, user, pass)
	if authErr != nil {
		log.Println(authErr)
		conn.Close()
		defer close(tidChan)
		return Session{}, authErr
	}
	log.Println("Connected to pundun node.")
	manChan := make(chan int, 1024)
	sendChan := make(chan Client, 65535)
	recvChan := make(chan []byte, 65535)

	go serverLoop(conn, manChan, sendChan, recvChan)
	go recvLoop(conn, recvChan)
	session.manChan = manChan
	session.sendChan = sendChan
	return session, nil
}

func Disconnect(s Session) {
	defer close(s.manChan)
	s.manChan <- stop
}

func GetTid(s Session) uint32 {
	tid := <-s.tidChan
	return uint32(tid)
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
				len := uint32(len(client.data))
				header := make([]byte, 6)
				binary.BigEndian.PutUint32(header, len+2)
				binary.BigEndian.PutUint16(header[4:], cid)
				cancel := make(chan bool)
				client.id = cid
				client.cancelTimer = cancel
				clients[cid] = client
				conn.Write(header)
				conn.Write(client.data)
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
			if strings.Contains(err.Error(),
				"use of closed network connection") {
				log.Printf("Connection closed.\n")
			} else {
				log.Printf("n: %v, error: %v\n", n, err.Error())
			}
			return
		}

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
