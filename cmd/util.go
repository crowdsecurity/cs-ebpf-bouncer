package cmd

type Origin struct {
	m map[string]uint32
}

func NewOrigin() *Origin {
	return &Origin{
		m: make(map[string]uint32),
	}
}

func (o *Origin) Add(origin string) uint32 {
	var (
		value  uint32
		exists bool
	)
	if value, exists = o.m[origin]; !exists {
		value = uint32(len(o.m) + 1)
		o.m[origin] = value
	}
	return value
}

func (o *Origin) Get(origin string) (uint32, bool) {
	if id, exists := o.m[origin]; exists {
		return id, true
	}
	return 0, false
}

func (o *Origin) GetFromValue(value uint32) string {
	for origin, id := range o.m {
		if id == value {
			return origin
		}
	}
	return ""
}
