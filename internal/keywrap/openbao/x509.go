package openbao

import "github.com/Infisical/agent-vault/internal/openbaoauth"

type SPIFFETLSSource = openbaoauth.SPIFFETLSSource
type X509Options = openbaoauth.X509Options
type X509TokenSource = openbaoauth.X509TokenSource

func NewX509TokenSource(options X509Options) (*X509TokenSource, error) {
	return openbaoauth.NewX509TokenSource(options)
}
