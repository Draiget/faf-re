package main

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ddsBytes builds a DDS file: an uncompressed 32-bit BGRA image (fourCC "") or DXT blocks.
func ddsBytes(w, h int, fourCC string, data []byte) []byte {
	head := make([]byte, ddsHeaderSize)
	le := binary.LittleEndian
	copy(head, "DDS ")
	le.PutUint32(head[4:], 124)
	le.PutUint32(head[8:], 0x1007)
	le.PutUint32(head[12:], uint32(h))
	le.PutUint32(head[16:], uint32(w))
	le.PutUint32(head[76:], 32)
	if fourCC != "" {
		le.PutUint32(head[80:], 0x4)
		copy(head[84:], fourCC)
	} else {
		le.PutUint32(head[80:], 0x41)
		le.PutUint32(head[88:], 32)
		le.PutUint32(head[92:], 0x00ff0000)
		le.PutUint32(head[96:], 0x0000ff00)
		le.PutUint32(head[100:], 0x000000ff)
		le.PutUint32(head[104:], 0xff000000)
	}
	le.PutUint32(head[108:], 0x1002)
	return append(head, data...)
}

// scmapBytes wraps a DDS in a version 2 .scmap header, as the game's map files start.
func scmapBytes(dds []byte) []byte {
	var b bytes.Buffer
	le := binary.LittleEndian
	b.WriteString("Map\x1a")
	_ = binary.Write(&b, le, int32(2))
	_ = binary.Write(&b, le, uint32(0xbeeffeed))
	_ = binary.Write(&b, le, int32(2))
	_ = binary.Write(&b, le, math.Float32bits(512))
	_ = binary.Write(&b, le, math.Float32bits(512))
	_ = binary.Write(&b, le, int32(0))
	_ = binary.Write(&b, le, int16(0))
	_ = binary.Write(&b, le, uint32(len(dds)))
	b.Write(dds)
	_ = binary.Write(&b, le, int32(56)) // the minor version; the terrain would follow
	return b.Bytes()
}

func TestPreviewUncompressed(t *testing.T) {
	// 2x2 pixels as BGRA bytes: red, green / blue, grey with a low alpha (drawn opaque).
	px := []byte{0, 0, 255, 255, 0, 255, 0, 255, 255, 0, 0, 255, 128, 128, 128, 27}
	file := scmapBytes(ddsBytes(2, 2, "", px))
	dds, err := scmapPreviewDDS(bytes.NewReader(file))
	if err != nil {
		t.Fatal(err)
	}
	img, err := decodeDDS(dds)
	if err != nil {
		t.Fatal(err)
	}
	want := map[[2]int][4]uint8{{0, 0}: {255, 0, 0, 255}, {1, 0}: {0, 255, 0, 255}, {0, 1}: {0, 0, 255, 255}, {1, 1}: {128, 128, 128, 255}}
	for at, c := range want {
		got := img.NRGBAAt(at[0], at[1])
		if [4]uint8{got.R, got.G, got.B, got.A} != c {
			t.Errorf("pixel %v = %v, want %v", at, got, c)
		}
	}
	if _, err := scmapPreviewDDS(bytes.NewReader([]byte("Map\x1a"))); err == nil {
		t.Error("a cut header gave a preview")
	}
	bad := append([]byte(nil), file...)
	copy(bad, "Nap\x1a")
	if _, err := scmapPreviewDDS(bytes.NewReader(bad)); err == nil {
		t.Error("a file that isn't a map gave a preview")
	}
}

func TestPreviewDXT1(t *testing.T) {
	// One 4x4 block: colour 0 red (565 0xF800), colour 1 blue (0x001F); pixel (1,0) takes colour 1, (2,0) the 2/3 mix.
	block := make([]byte, 8)
	binary.LittleEndian.PutUint16(block[0:], 0xF800)
	binary.LittleEndian.PutUint16(block[2:], 0x001F)
	binary.LittleEndian.PutUint32(block[4:], 1<<2|2<<4)
	img, err := decodeDDS(ddsBytes(4, 4, "DXT1", block))
	if err != nil {
		t.Fatal(err)
	}
	if c := img.NRGBAAt(0, 0); c.R != 255 || c.B != 0 || c.A != 255 {
		t.Errorf("(0,0) %v", c)
	}
	if c := img.NRGBAAt(1, 0); c.R != 0 || c.B != 255 {
		t.Errorf("(1,0) %v", c)
	}
	if c := img.NRGBAAt(2, 0); c.R != 170 || c.B != 85 {
		t.Errorf("(2,0) %v", c)
	}
	if _, err := decodeDDS(ddsBytes(4, 4, "ATI2", block)); err == nil {
		t.Error("an unknown format decoded")
	}
}

const adrasteaLikeSave = `Scenario = {
    MasterChain = {
        ['_MASTERCHAIN_'] = {
            Markers = {
                ['Mass 1'] = {
                    ['type'] = STRING( 'Mass' ),
                    ['position'] = VECTOR3( 10, 1, 10 ),
                },
                ['ARMY_2'] = {
                    ['color'] = STRING( 'ff800080' ),
                    ['type'] = STRING( 'Blank Marker' ),
                    ['orientation'] = VECTOR3( 0, -0, 0 ),
                    ['position'] = VECTOR3( 487.5, 45.3, 378.5 ),
                },
                ['ARMY_1'] = {
                    ['color'] = STRING( 'ff800080' ),
                    ['type'] = STRING( 'Blank Marker' ),
                    ['orientation'] = VECTOR3( 0, -0, 0 ),
                    ['position'] = VECTOR3( 24.5, 45.3047, 133.5 ),
                },
            },
        },
    },
    Armies = {
        ['ARMY_1'] =
        {
            personality = '',
            Economy = { mass = 0, energy = 0, },
        },
    },
}
`

func TestParseSpawns(t *testing.T) {
	got := parseSpawns(adrasteaLikeSave, []string{"ARMY_1", "ARMY_2"}, [2]int{512, 512})
	want := [][2]float64{{0.0479, 0.2607}, {0.9521, 0.7393}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("spawns %v, want %v", got, want)
	}
	if got := parseSpawns(adrasteaLikeSave, []string{"ARMY_1", "ARMY_2", "ARMY_3"}, [2]int{512, 512}); got != nil {
		t.Fatalf("an army without a marker gave %v", got)
	}
	if got := scenarioArmies(setonsScenario); len(got) != 8 || got[0] != "ARMY_1" || got[7] != "ARMY_8" {
		t.Fatalf("armies %v", got)
	}
}

func TestScanMapsSpawnsAndPreview(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "two.v0001")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	scenario := strings.ReplaceAll(strings.ReplaceAll(setonsScenario, "{1024, 1024}", "{512, 512}"),
		"'ARMY_1','ARMY_2','ARMY_3','ARMY_4','ARMY_5','ARMY_6','ARMY_7','ARMY_8',", "'ARMY_1','ARMY_2',")
	// The scenario names its files (in another case than the folder's, as the vault's are on Linux), and its own name
	// isn't their prefix: a folder can hold several scenarios over one map.
	scenario = strings.Replace(scenario, "map = '/maps/SCMP_009/SCMP_009.scmap',", "map = '/maps/two.v0001/TWO.scmap',\n    save = '/maps/two.v0001/Two_save.lua',", 1)
	files := map[string][]byte{
		"Alpha_scenario.lua": []byte(scenario),
		"two_save.lua":       []byte(adrasteaLikeSave),
		"two.scmap":          scmapBytes(ddsBytes(2, 2, "", make([]byte, 16))),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(folder, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	maps := scanMaps([]mapDir{{"vault", dir}})
	if len(maps) != 1 || len(maps[0].Spawns) != 2 || maps[0].Preview != "/api/v1/maps/two.v0001/preview.png" || maps[0].Players != 2 {
		t.Fatalf("maps %+v", maps)
	}
	a := &api{token: "0123456789abcdef0123", maps: func() []Map { return maps }, m: testManager(t)}
	for _, path := range []string{"/api/v1/maps/two.v0001/preview.png", "/api/v1/public/maps/two.v0001/preview.png"} {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", path, nil)) // no token: an <img> can't send one
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/png" {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		img, err := png.Decode(w.Body)
		if err != nil || img.Bounds().Dx() != 2 {
			t.Fatalf("%s: PNG %v %v", path, err, img)
		}
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/maps/nope/preview.png", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("an unknown map's preview: %d", w.Code)
	}
	// A map without its .scmap has no preview.
	if err := os.Remove(filepath.Join(folder, "two.scmap")); err != nil {
		t.Fatal(err)
	}
	if maps := scanMaps([]mapDir{{"vault", dir}}); maps[0].Preview != "" {
		t.Fatalf("preview without a map file: %q", maps[0].Preview)
	}
}

// TestSampledMaps reads real map folders when SERVER_HOST_MAP_SAMPLES names a folder of them (none are in the repo).
func TestSampledMaps(t *testing.T) {
	dir := os.Getenv("SERVER_HOST_MAP_SAMPLES")
	if dir == "" {
		t.Skip("SERVER_HOST_MAP_SAMPLES isn't set")
	}
	maps := scanMaps([]mapDir{{"sample", dir}})
	if len(maps) == 0 {
		t.Fatalf("no maps in %s", dir)
	}
	var cache previewCache
	withSpawns, withPreview := 0, 0
	for _, mp := range maps {
		if len(mp.Spawns) == mp.Players {
			withSpawns++
		} else {
			t.Logf("%s: %d start spots of %d players read", mp.ID, len(mp.Spawns), mp.Players)
		}
		if mp.Preview == "" {
			continue
		}
		data, err := cache.get(mp.scmapFile)
		if err != nil {
			t.Errorf("%s: %v", mp.ID, err)
			continue
		}
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Errorf("%s: %v", mp.ID, err)
			continue
		}
		withPreview++
		if mp.ID == "adaptive_adrastea.v0004" {
			t.Logf("%s: %d spawns, first %v; preview %dx%d, %d bytes of PNG", mp.ID, len(mp.Spawns), mp.Spawns[0], img.Bounds().Dx(), img.Bounds().Dy(), len(data))
		}
	}
	t.Logf("%d maps: %d with every start spot, %d previews decoded", len(maps), withSpawns, withPreview)
	if withPreview == 0 || withSpawns == 0 {
		t.Fatal("no preview or no start spots read")
	}
}
