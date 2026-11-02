package fafclient

import (
	"path/filepath"
	"slices"
	"testing"
)

// The order IceAdapterImplTest asserts in downlords-faf-client develop 66e624f119.
func TestCommandMatchesClient(t *testing.T) {
	a := Adapter{Java: "java", NativeDir: "natives", JavaFXClassPath: "javafx-base.jar"}
	got := a.Command(Player{ID: 1, Login: "Alpha"}, 4711, 2000, 3000, "tok", "http://api/ice")
	cp := filepath.Join("natives", "faf-ice-adapter.jar") + string(filepath.ListSeparator) + "javafx-base.jar"
	want := []string{
		"java", "-XX:+UseZGC", "-Xms128m", "-Xmx512m", "-Dorg.ice4j.ipv6.DISABLED=true",
		"-cp", cp, "com.faforever.iceadapter.IceAdapter",
		"--id", "1", "--game-id", "4711", "--login", "Alpha",
		"--rpc-port", "2000", "--gpgnet-port", "3000",
		"--access-token", "tok", "--icebreaker-base-url", "http://api/ice",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("command\n got %q\nwant %q", got, want)
	}
}

func TestCommandNativeAdapterHasNoJvmOptions(t *testing.T) {
	a := Adapter{Exe: "faf-netbridge.exe"}
	got := a.Command(Player{ID: 1, Login: "Alpha"}, 4711, 2000, 3000, "tok", "http://api/ice")
	if got[0] != "faf-netbridge.exe" || got[1] != "--id" {
		t.Fatalf("command %q", got)
	}
}
