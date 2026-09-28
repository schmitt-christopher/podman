//go:build darwin || freebsd || linux

package certificates

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuestCopyCommand(t *testing.T) {
	for _, folder := range []string{
		"FirstLast",
		"First Last",
		"First(Last",
		"First (Last)",
		"O'Connor",
		`First"Last`,
		"First$Last",
		"First$(printf changed)Last",
		"First`printf changed`Last",
	} {
		t.Run(folder, func(t *testing.T) {
			sourceDir := filepath.Join(t.TempDir(), folder)
			require.NoError(t, os.MkdirAll(sourceDir, 0o755))
			source := filepath.Join(sourceDir, CertificatesFileName)
			contents := []byte("certificate bundle\n")
			require.NoError(t, os.WriteFile(source, contents, 0o600))
			destination := filepath.Join(t.TempDir(), CertificatesFileName)

			// Run the guest command without privileges, copying to a temporary destination.
			command := `destination=$1
sudo() {
	[ "$#" -eq 3 ] && [ "$1" = cp ] && [ "$3" = /etc/pki/ca-trust/source/anchors ] || return 1
	command cp -- "$2" "$destination"
}
` + guestCopyCommand(source)
			output, err := exec.CommandContext(t.Context(), "sh", "-c", command, "sh", destination).CombinedOutput()
			require.NoError(t, err, "%s", output)

			copied, err := os.ReadFile(destination)
			require.NoError(t, err)
			assert.Equal(t, contents, copied)
		})
	}
}
