// !building +testing

package query

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetermineServer(t *testing.T) {
	require.Equal(t, ApnicServer, DetermineWhoisServerForIP(net.ParseIP("8.8.8.8")))
	require.Equal(t, RipeServer, DetermineWhoisServerForIP(net.ParseIP("7.6.5.4")))
}
