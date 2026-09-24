package main

import "flag"

type scanFlags struct {
	*flag.FlagSet
	format  string
	output  string
	failOn  string
	waivers string
}

func newFlagSet() *scanFlags {
	fs := &scanFlags{FlagSet: flag.NewFlagSet("scan", flag.ContinueOnError)}
	fs.StringVar(&fs.format, "format", "terminal", "terminal, json or sarif")
	fs.StringVar(&fs.output, "output", "", "write the report here instead of stdout")
	fs.StringVar(&fs.failOn, "fail-on", "low", "lowest severity that fails the run: low, medium, high or critical")
	fs.StringVar(&fs.waivers, "waivers", "", "path to a waivers YAML file")
	return fs
}
