//go:build (linux && 386) || (linux && amd64) || (linux && arm64)

package kernel

func utsnameStr(in []int8) string {
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			break
		}
		out = append(out, byte(in[i]))
	}
	return string(out)
}
