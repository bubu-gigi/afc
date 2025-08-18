package flags

type GlobalOptions struct {
    DumpRequestBodies bool
    SkipWazuhSend     bool
}

var (
	EnableLogging     bool
	DumpRequestBodies bool
	SkipWazuhSend     bool
	ArtifactFilter    []string

	ValidArtifacts = []string{
		"evtx",
		"hive",
		"mft",
		"pf",
		"job",
		"taskxml",
		"rbin",
		"lnk",
		"jl",
		"ps",
		"journal",
	}
)
