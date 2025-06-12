package xdp

type OriginType struct {
	m map[string]uint32
}

var Origin *OriginType

func NewOrigin() *OriginType {
	return &OriginType{
		m: make(map[string]uint32),
	}
}

func (o *OriginType) Add(origin string) uint32 {
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

func (o *OriginType) GetFromString(origin string) (uint32, bool) {
	if id, exists := o.m[origin]; exists {
		return id, true
	}
	return 0, false
}

func (o *OriginType) GetFromValue(value uint32) string {
	for origin, id := range o.m {
		if id == value {
			return origin
		}
	}
	if value == 0 {
		return "processed"
	}

	return "unknown"
}

func (o *OriginType) Len() int {
	return len(o.m)
}
