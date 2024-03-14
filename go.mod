module tls-client-go

go 1.18

require (
	github.com/andybalholm/brotli v1.0.4
	github.com/elliotchance/pie/v2 v2.0.1
	github.com/refraction-networking/utls v1.1.0
	github.com/sirupsen/logrus v1.9.0
	golang.org/x/exp v0.0.0-20220321173239-a90fa8a75705
	golang.org/x/net v0.0.0-20220520000938-2e3eb7b945c2
)

require (
	golang.org/x/crypto v0.0.0-20220518034528-6f7dac969898 // indirect
	golang.org/x/sys v0.2.0 // indirect
	golang.org/x/text v0.4.0 // indirect
)

replace golang.org/x/net => ./net

replace github.com/refraction-networking/utls => ./utls
