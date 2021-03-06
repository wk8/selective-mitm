package selective_mitm

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

// a CA cert and a server signed by that CA's cert/key pairs for test.
const (
	caCert = `-----BEGIN CERTIFICATE-----
MIIDwTCCAqmgAwIBAgIUX0/al5rajt4+zbxOAjHrDUXb4RUwDQYJKoZIhvcNAQEL
BQAwcDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM
DVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBFdpc2gxDjAMBgNVBAsMBUluZnJhMRUw
EwYDVQQDDAw3MTg2ZTE5MjdhNjQwHhcNMjAwOTI0MTgwNTMxWhcNMjMwNjIxMTgw
NTMxWjBwMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UE
BwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwEV2lzaDEOMAwGA1UECwwFSW5mcmEx
FTATBgNVBAMMDDcxODZlMTkyN2E2NDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBANMDhui2ueCgnm5MteX1qLCEDdnPim7sgdVXbWIPu+3+cnFNZG+t5ScS
1TQhvAP3D/v5J/1xNRMmdkyV/dBPVqhzSJZ78QSFwNUaC+NTQBPPu1EwyZl5CnMs
HRmT23XovCDpM6fiPs4zyB/ZFcMCfihNqDRwGAFrdNJwsu2ysnI9JKp4SDnpro9/
jLzFl3SHPn/Uo7qYftoJQaBDv/rtUQwgknNuihzxNyhGXbeRCxCzEh2/p5bSmVxf
e0TH5+L0DN9K4fNEqMJ9vOPc00AYvX1vBVaEMOOcDIVyiiscbmhxHSh5VtNn61JH
MR86r5d+AsgakUCOgYLvqERSwbg/jEECAwEAAaNTMFEwHQYDVR0OBBYEFLNNZ6H9
hAlL8VDmbWg5b/CWf8ulMB8GA1UdIwQYMBaAFLNNZ6H9hAlL8VDmbWg5b/CWf8ul
MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACOx1MxeEI8oNVgp
KWsXXmMDnjNWYU4hbJw2dIIz24LLGfRxVM+7rrdLGek4fZgOUGmWhZDJTiE4u9nA
aa44yv1jk4JXsq20GlHh/Vxeebah8ZkjKswOpHtYay+Oa57SIeC0ixZdNdAyeWJd
qHnV5dGySASIWUkiRDvPAbSAfXbS0l5W69hZRQpO6c2waPdy+Eit9MLBTY7Qavyv
33AZJj7MWwvvffHp/x/zrxZK7K91lF76cdiG6dn/M2JXRV2dqqcdqK31GU1hrbVB
mfis3I7P6mS59lgM0Hcc+SlURIAloWbsZH61aHUdMqsfgBe1kqkoOnrBFjXhN/G0
N02iITg=
-----END CERTIFICATE-----`

	serverCert = `-----BEGIN CERTIFICATE-----
MIIDvzCCAqegAwIBAgIJAPR3IcR8uA3xMA0GCSqGSIb3DQEBCwUAMHAxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp
c2NvMQ0wCwYDVQQKDARXaXNoMQ4wDAYDVQQLDAVJbmZyYTEVMBMGA1UEAwwMNzE4
NmUxOTI3YTY0MB4XDTIwMDkyOTAwNTMwNFoXDTIxMDkyOTAwNTMwNFowajELMAkG
A1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUx
DDAKBgNVBAoMA3drODEMMAoGA1UECwwDd2s4MRgwFgYDVQQDDA9sb2NhbGhvc3Qu
bG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmzvBW5/Hy+0RI
VGxp6h289/x/br6Y1hNubTmvnaLF69fLTmmSvO4KhjRRWyz2iU6+DYDYNHDWCFM9
ydwcFArLWljM5REJsMOC5PRBjFMIDy4gAP4nfFjpMsD1EDwJzhh9ISlxO/ZcZPu4
80SGdlhRwGpyq+3n3weApB5lEQa7jLkS2uzGqByNESYnXY0Ix+IM8IDB+sQxARQx
/UcL81CDOGdcMw3uB/sS/VkJ27k+LMj15ExiVsIonDi48NnKS1yB94k8k8uqg4L1
3CBWDIoIxqZ1E276id+VjGWeu3X5tcHYDs5lk00n9VRLDZdRzFsPxkpb+z11P6nD
SrCkyaMNAgMBAAGjYjBgMB8GA1UdIwQYMBaAFLNNZ6H9hAlL8VDmbWg5b/CWf8ul
MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMCUGA1UdEQQeMByCD2xvY2FsaG9zdC5s
b2NhbIIJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQAbMWY9lWly856NEyX+
2bOEv4R9fuv820cq3iRKDWJHvHvcvuW5WyFDlV3uJgybdHeOHKSZ6KP/+iLKAXfH
oLxrN7I+pb5j9sHDsc2Nxxq4Uyf8uo3BvY4dsFBvNMOVmkNL/35VL2DI3K0qHjav
1lEYhgcQgOjkNar7Wz5EZIqsPmlZ6heuvKwAQ5kfdNyT2ek3+Dh7k60EtOxjKxRv
2fB9cBgliZQP7tqZZUEC45mr4xWGtLLDV0BQ+/xtBroI0FBrWjM65NcDl1C5GNL6
Zk5yeZyj9ii2B+Fn92YYsE6XXjk9l1v625WuH2Ih0V0963CPUWUedwL2XPKVEjWk
T+kb
-----END CERTIFICATE-----`

	serverKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAps7wVufx8vtESFRsaeodvPf8f26+mNYTbm05r52ixevXy05p
krzuCoY0UVss9olOvg2A2DRw1ghTPcncHBQKy1pYzOURCbDDguT0QYxTCA8uIAD+
J3xY6TLA9RA8Cc4YfSEpcTv2XGT7uPNEhnZYUcBqcqvt598HgKQeZREGu4y5Etrs
xqgcjREmJ12NCMfiDPCAwfrEMQEUMf1HC/NQgzhnXDMN7gf7Ev1ZCdu5PizI9eRM
YlbCKJw4uPDZyktcgfeJPJPLqoOC9dwgVgyKCMamdRNu+onflYxlnrt1+bXB2A7O
ZZNNJ/VUSw2XUcxbD8ZKW/s9dT+pw0qwpMmjDQIDAQABAoIBAQCR/Z+fkBTTwlG6
tBjGgd5RGwFkTnqFrScIiJPqPZ7OdmFBUHlZsfzsPRTg91lc1EOUVqEjmJIA4Pxp
oZgBAxGHdKUvfnPw9UHH97ZHABdTgGWwIO5PhKcUQhVa5kCFnFkWesWYkxBFQSSG
dHLO9BjMRAlmH09ylmIslnb7oXExBsjij7i8E6PNzztRqLTkpcSACqmw6WtMTcim
ZjNUyrhQwh+/u7BYWSrmAKIoMAmU3KMz6no9i5QNQMHOyde7hFI1XWXe4iYmGVOK
sGdMWjhp/JQpvFWhItNxTfD8jUeTf7MFuXV6mkmD4FxmEHTJ7ST/qkxa/c2qMCz5
mzxCjX7JAoGBAM+KeAQFQeyN+j1Rax4tTetbnMo4AdwyUleBf9rzjk/t59dpqkmT
+1EzpHmNG9tn72LB2C5KLIaBl8K4+oZ+bNXDB9G+gRmTKqs+jnvZKtU/4OXrGB47
7qvBPvj3x9dG8moal9XV9HyfdKbC+ucksA4NHknv68eFRtEaPEy4NSD7AoGBAM3B
ug+KolM7OxwkAhitB4o/LhbpAbKiVY7jJLaE5QUH6y7YxCmxYzDBAilLxP3HyXsW
rlF+EckRzNzVe6peBDAibDwDLuzciIwAltbI38ritUpBA+DvV6LRybbWUqQKrq0B
79sPG69zhrOyoVZJJg2hHuaueyC+cvsgS0TX6F2XAoGBAJdTBkkgMD40E1asS+dX
7y2BweOsTKbqRiGpubjCx2w+MkJduB0n+iHt/qnmGn6y3NfsMR0nVinIygff6kMw
YVjHeKcVOXqVVJJB7ZAd+1470layQQaielbfc3QC7sJn5483zqfK9hX8Cgkht+Hb
XUcRh5kvh4IWClmiwH7L/WkLAoGBAIY01WKrv4NggAaz6fYkbmWbHjntU6Erx3jC
6cBvYF5ustVEqHa1cIhtbDZ5aI1L0jyKJ7uZ6onnJWPpj5cpabvnyAdA4Eu48Qu4
mqqQLYDNbQh47cm688OM6PBsTU0YdqT8PXH6IcnIJdVyL0/zuHFtZZV7u245KxBo
GRBXcAYTAoGBAMDru2FHwvTYGM3fhN/1iJZDcKS394I/kVjTe0nPXoanoj7Bay1J
ekdPqctyedlbBLCNQ3JiUUZxDKq1aLGmKg77zLGPBQlhKrfpphwaefr805TbF2mK
kk3t+A1GaULCWrl7n3ATRvE4uSig8OhkJEUywAX0TKQkm5mKUbN+p/nn
-----END RSA PRIVATE KEY-----`
)

func getServerCertificate(t *testing.T) *tls.Certificate {
	cert, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
	require.NoError(t, err)
	return &cert
}

func tlsConfig(t *testing.T) *tls.Config {
	rootCAs := x509.NewCertPool()
	require.True(t, rootCAs.AppendCertsFromPEM([]byte(caCert)))

	return &tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}
}
