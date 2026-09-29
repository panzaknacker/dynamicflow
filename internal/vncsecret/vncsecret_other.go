//go:build !linux

package vncsecret

import "errors"

var (
	ErrUnsafeState = errors.New("unsafe VNC credential state")
	ErrService     = errors.New("VNC service validation failed")
	ErrUnsupported = errors.New("VNC credential operation is unsupported")
)

func Reveal() ([]byte, error) { return nil, ErrUnsupported }
func Rotate() ([]byte, error) { return nil, ErrUnsupported }
