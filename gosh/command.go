package gosh

import (
	"fmt"
	"strings"
)

type goshCommandSpec struct {
	script string
	argv0  string
	params []string
}

func goshParseCommand(args []string) (*goshCommandSpec, error) {
	var spec *goshCommandSpec
	for i := 1; i < len(args); i++ {
		if args[i] != "-c" {
			continue
		}
		if spec != nil {
			return nil, fmt.Errorf("gosh: multiple -c options are not supported")
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("gosh: -c requires a command string")
		}
		spec = &goshCommandSpec{
			script: strings.Clone(args[i+1]),
			argv0:  strings.Clone(args[0]),
		}
		if i+2 < len(args) {
			spec.argv0 = strings.Clone(args[i+2])
			if i+3 < len(args) {
				rest := args[i+3:]
				spec.params = make([]string, len(rest))
				for j, val := range rest {
					spec.params[j] = strings.Clone(val)
				}
			}
		}
		break
	}
	return spec, nil
}
