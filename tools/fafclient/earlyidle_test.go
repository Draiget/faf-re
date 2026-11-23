package fafclient

// Issue #483: a launcher that accepts the game's GPGNet connection itself and
// connects to the adapter only once the adapter listens (FAForeverRustClient's
// GpgNetProxy) hands the adapter a GameState Idle that is already waiting in
// the socket when the adapter accepts. FAF's Java adapter reads it before it
// has stored the new connection as its current client, its telemetry throws,
// the read thread dies and the socket closes: the game waits on "Connecting..."
// for ever. An adapter must answer CreateLobby and keep the connection.
//
// Integration test, skipped unless an adapter is named:
//
//	FAF_EARLYIDLE_EXE=<faf-netbridge.exe> go test ./fafclient -run EarlyIdle -v
//
// The same test against FAF's adapter (expected to fail, as the control):
//
//	FAF_EARLYIDLE_JAVA=<java.exe> FAF_EARLYIDLE_JAR_DIR=<folder with faf-ice-adapter.jar>
//	FAF_EARLYIDLE_JAVAFX=<the client's javafx-* jars, path-list separated>
//
// FAF_EARLYIDLE_ROUNDS sets the number of adapter starts (default 10).
// FAF_EARLYIDLE_WRITE_DELAY_MS waits that long between connecting and writing
// Idle (a launcher-side delay, or a game's own connect-to-Idle time).
// FAF_EARLYIDLE_AFTER_RPC=1 connects only after the adapter answered
// setLobbyInitMode, as the Java client starts the game; with it the "case
// not exercised" check is skipped.
// FAF_EARLYIDLE_LOGDIR keeps each adapter's LOG_DIR and output there, one
// folder per round. The Java adapter only throws while its telemetry debugger
// is registered; check its log for "gameState must not change to null".

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"faf-main/tools/gpgnet"
)

// earlyIdleEnvMs reads a whole number of milliseconds from the environment (0
// when unset or invalid).
func earlyIdleEnvMs(name string) int {
	v, err := strconv.Atoi(os.Getenv(name))
	if err != nil || v < 0 {
		return 0
	}
	return v
}

func earlyIdleAdapter(t *testing.T) Adapter {
	if exe := os.Getenv("FAF_EARLYIDLE_EXE"); exe != "" {
		return Adapter{Exe: exe, NativeDir: "."}
	}
	if java := os.Getenv("FAF_EARLYIDLE_JAVA"); java != "" {
		return Adapter{Java: java, NativeDir: os.Getenv("FAF_EARLYIDLE_JAR_DIR"), JavaFXClassPath: os.Getenv("FAF_EARLYIDLE_JAVAFX")}
	}
	t.Skip("set FAF_EARLYIDLE_EXE or FAF_EARLYIDLE_JAVA to run")
	return Adapter{}
}

// earlyIdleRound starts one adapter and plays the proxy. It returns how long
// the proxy waited for the adapter's GPGNet port, and the failure, if any.
func earlyIdleRound(t *testing.T, a Adapter) (time.Duration, error) {
	rpcPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	gpgPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	argv := a.Command(Player{ID: 4830, Login: "early"}, 483, rpcPort, gpgPort, "token", "http://127.0.0.1:1/ice")
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = a.NativeDir
	logDir := t.TempDir()
	if keep := os.Getenv("FAF_EARLYIDLE_LOGDIR"); keep != "" {
		logDir = keep + "/" + strconv.Itoa(gpgPort)
		_ = os.MkdirAll(logDir, 0o755)
	}
	cmd.Env = append(os.Environ(), "LOG_DIR="+logDir)
	if f, err := os.Create(logDir + "/adapter-stdout.log"); err == nil {
		defer f.Close()
		cmd.Stdout, cmd.Stderr = f, f
	}
	idle, err := gpgnet.Encode(gpgnet.New("GameState", "Idle"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if os.Getenv("FAF_EARLYIDLE_LOGDIR") != "" {
			time.Sleep(time.Second) // let the adapter finish writing a stack trace
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// The client's side: RPC connect and setLobbyInitMode, as IceAdapterImpl,
	// at the same time as the proxy below (the Rust client starts both together).
	rpcReady := make(chan struct{})
	go func() {
		for attempt := 0; attempt < connectAttempts && ctx.Err() == nil; attempt++ {
			conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(rpcPort), time.Second)
			if err != nil {
				time.Sleep(connectDelay)
				continue
			}
			go func() { <-ctx.Done(); conn.Close() }()
			peer := NewPeer(conn, nil)
			go func() { _ = peer.Serve(conn, func(Message) {}) }()
			if reply, err := peer.Call("setLobbyInitMode", "normal"); err == nil {
				select {
				case <-reply:
				case <-ctx.Done():
				}
			}
			close(rpcReady)
			return
		}
	}()

	// The Java client's order instead: the game starts once the adapter has
	// answered over RPC, so it connects to an adapter that already listens.
	if earlyIdleEnvMs("FAF_EARLYIDLE_AFTER_RPC") > 0 {
		select {
		case <-rpcReady:
		case <-time.After(30 * time.Second):
			return 0, errors.New("adapter never answered over RPC")
		}
	}

	// The proxy: the game's Idle is already held; connect as soon as the
	// adapter listens and pass it on at once.
	start := time.Now()
	var game net.Conn
	dials := 0
	for game == nil {
		if time.Since(start) > 30*time.Second {
			return time.Since(start), errors.New("adapter never listened on its GPGNet port")
		}
		dials++
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(gpgPort), time.Second)
		if err != nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		game = c
	}
	waited := time.Since(start)
	if dials == 1 {
		waited = 0 // the adapter already listened: not the case under test
	}
	defer game.Close()
	if d := earlyIdleEnvMs("FAF_EARLYIDLE_WRITE_DELAY_MS"); d > 0 {
		time.Sleep(time.Duration(d) * time.Millisecond)
	}
	if _, err := game.Write(idle); err != nil {
		return waited, err
	}

	r := bufio.NewReader(game)
	_ = game.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		m, err := gpgnet.ReadMessage(r)
		if err != nil {
			return waited, errors.New("no CreateLobby: " + err.Error())
		}
		if m.Command == "CreateLobby" {
			break
		}
	}
	// The game opens its lobby and reports it; the connection must stay.
	if err := gpgnet.WriteMessage(game, gpgnet.New("GameState", "Lobby")); err != nil {
		return waited, errors.New("write Lobby: " + err.Error())
	}
	_ = game.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, err := gpgnet.ReadMessage(r)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return waited, nil
		}
		if errors.Is(err, io.EOF) || err != nil {
			return waited, errors.New("connection closed after CreateLobby: " + err.Error())
		}
	}
}

func TestEarlyIdleBeforeAccept(t *testing.T) {
	a := earlyIdleAdapter(t)
	rounds := 10
	if v, err := strconv.Atoi(os.Getenv("FAF_EARLYIDLE_ROUNDS")); err == nil && v > 0 {
		rounds = v
	}
	failed, waitedRounds := 0, 0
	for i := 0; i < rounds; i++ {
		waited, err := earlyIdleRound(t, a)
		if waited > 0 {
			waitedRounds++
		}
		if err != nil {
			failed++
			t.Logf("round %d: proxy waited %v: FAIL: %v", i+1, waited.Round(time.Millisecond), err)
		} else {
			t.Logf("round %d: proxy waited %v: ok", i+1, waited.Round(time.Millisecond))
		}
	}
	if waitedRounds == 0 && earlyIdleEnvMs("FAF_EARLYIDLE_AFTER_RPC") == 0 {
		t.Fatalf("the adapter listened before the proxy's first dial in every round; the case was not exercised")
	}
	if failed > 0 {
		t.Fatalf("%d of %d rounds lost the game's connection", failed, rounds)
	}
}
