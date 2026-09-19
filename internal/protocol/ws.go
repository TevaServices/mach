package protocol

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSConn wraps a websocket connection with JSON envelope framing and a
// write mutex (gorilla: one reader + one writer at a time). Every write
// carries a deadline so a peer that stops reading cannot wedge a writer
// (and the mutex) forever.
type WSConn struct {
	conn *websocket.Conn
	wmu  sync.Mutex
}

// writeTimeout bounds every envelope/ping write; the peer has this long to
// drain TCP before the write fails and the connection is torn down.
const writeTimeout = 30 * time.Second

func NewWSConn(c *websocket.Conn) *WSConn { return &WSConn{conn: c} }

func (w *WSConn) WriteEnvelope(env Envelope) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	_ = w.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return w.conn.WriteJSON(env)
}

func (w *WSConn) ReadEnvelope() (Envelope, error) {
	var env Envelope
	if err := w.conn.ReadJSON(&env); err != nil {
		return Envelope{}, err
	}
	return env, nil
}

func (w *WSConn) Close() error { return w.conn.Close() }

// Ping sends a protocol-level ping frame.
func (w *WSConn) Ping() error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	_ = w.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return w.conn.WriteMessage(websocket.PingMessage, nil)
}

func (w *WSConn) SetPongHandler(h func(string) error) { w.conn.SetPongHandler(h) }
func (w *WSConn) SetReadDeadline(t time.Time) error   { return w.conn.SetReadDeadline(t) }
func (w *WSConn) SetWriteDeadline(t time.Time) error  { return w.conn.SetWriteDeadline(t) }

// SetReadLimit bounds one inbound frame. A peer that exceeds it is closed by the
// read, which is what makes an unbounded frame the peer's problem rather than
// this process's: ReadEnvelope buffers a whole frame before decoding, and
// gorilla's default is no limit at all.
func (w *WSConn) SetReadLimit(n int64) { w.conn.SetReadLimit(n) }
