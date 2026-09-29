package gpgnet

import "fmt"

// WireArg carries one argument through JSON without losing its GPGNet type:
// plain JSON would turn int32 into float64 and binary data into text.
type WireArg struct {
	I *int32  `json:"i,omitempty"`
	S *string `json:"s,omitempty"`
	D []byte  `json:"d,omitempty"`
}

// EncodeArgs converts arguments for JSON transport.
func EncodeArgs(args []any) []WireArg {
	out := make([]WireArg, 0, len(args))
	for _, a := range New("", args...).Args {
		switch v := a.(type) {
		case int32:
			out = append(out, WireArg{I: &v})
		case string:
			out = append(out, WireArg{S: &v})
		case Data:
			out = append(out, WireArg{D: append([]byte{}, v...)})
		case []byte:
			out = append(out, WireArg{D: append([]byte{}, v...)})
		default:
			s := fmt.Sprint(v)
			out = append(out, WireArg{S: &s})
		}
	}
	return out
}

// DecodeArgs restores arguments encoded by EncodeArgs.
func DecodeArgs(in []WireArg) []any {
	out := make([]any, 0, len(in))
	for _, w := range in {
		switch {
		case w.I != nil:
			out = append(out, *w.I)
		case w.S != nil:
			out = append(out, *w.S)
		default:
			out = append(out, Data(w.D))
		}
	}
	return out
}
