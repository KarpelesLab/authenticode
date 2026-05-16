module github.com/KarpelesLab/authenticode/example/sign

go 1.25.3

require (
	github.com/KarpelesLab/authenticode v0.0.0
	github.com/KarpelesLab/hsm v0.2.5
)

require (
	github.com/boltdb/bolt v1.3.1 // indirect
	github.com/enceve/crypto v0.0.0-20160707101852-34d48bb93815 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/term v0.43.0 // indirect
)

replace github.com/KarpelesLab/authenticode => ../..
