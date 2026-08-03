// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package collectors

import (
	"context"
	"fmt"
	"path"
	"strings"

	configfilesdiscoveryimpl "github.com/DataDog/datadog-agent/comp/core/configfilesdiscovery/impl"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func unwrapShellCommandline(args []string) []string {
	if len(args) < 3 || !isShellExecutable(args[0]) || args[1] != "-c" {
		return args
	}
	return strings.Fields(args[2])
}

func isShellExecutable(arg string) bool {
	switch path.Base(arg) {
	case "sh", "bash", "dash", "ash", "zsh":
		return true
	default:
		return false
	}
}

func resolveConfigPath(configPath string, workingDir string) (string, bool) {
	if configPath == "" || strings.ContainsRune(configPath, 0) {
		return "", false
	}
	if path.IsAbs(configPath) {
		return path.Clean(configPath), true
	}
	if !path.IsAbs(workingDir) {
		return "", false
	}
	return path.Clean(path.Join(workingDir, configPath)), true
}

// findConfigPath tries the runtime-native command first, then falls back to
// command lines discovered from live processes. Returns the resolved path and
// whether an explicit config argument was found.
func findConfigPath(ctx context.Context, integration string, reader configfilesdiscoveryimpl.ConfigReader, findConfigArg func([]string) (string, bool)) (string, bool, error) {
	commandline, runtimeErr := reader.ReadRuntimeCommandline(ctx)
	matched := false
	if runtimeErr == nil {
		if configArg, found := findConfigArg(commandline.Args); found {
			matched = true
			if configPath, resolved := resolveConfigPath(configArg, commandline.WorkingDir); resolved {
				log.Debugf("config files discovery found explicit config path for integration %q from runtime command line: %q", integration, configPath)
				return configPath, true, nil
			}
			log.Debugf("config files discovery found an explicit config argument for integration %q in the runtime command line but could not resolve path %q from working directory %q", integration, configArg, commandline.WorkingDir)
		}
	} else {
		log.Debugf("config files discovery could not read runtime command line for integration %q; checking live process command lines: %v", integration, runtimeErr)
	}

	var configPath string
	for _, commandline := range reader.ReadLiveProcessCommandlines(ctx) {
		configArg, found := findConfigArg(commandline.Args)
		if !found {
			continue
		}
		matched = true
		resolvedPath, resolved := resolveConfigPath(configArg, commandline.WorkingDir)
		if !resolved {
			log.Debugf("config files discovery found an explicit config argument for integration %q in a live process command line but could not resolve path %q from working directory %q", integration, configArg, commandline.WorkingDir)
			return "", true, runtimeErr
		}
		if configPath != "" && configPath != resolvedPath {
			log.Debugf("config files discovery found conflicting explicit config paths for integration %q in live process command lines: %q and %q", integration, configPath, resolvedPath)
			return "", true, runtimeErr
		}
		configPath = resolvedPath
	}
	if configPath != "" {
		log.Debugf("config files discovery found explicit config path for integration %q from live process command lines: %q", integration, configPath)
		return configPath, true, nil
	}
	return "", matched, runtimeErr
}

// readConfigFile discovers and reads an explicit config file, or falls back to
// default paths when no explicit config argument is found. Returns the
// file and whether exactly one file was selected.
func readConfigFile(
	ctx context.Context,
	integration string,
	reader configfilesdiscoveryimpl.ConfigReader,
	findConfigArg func([]string) (string, bool),
	defaultPaths []string,
) (configfilesdiscoveryimpl.ConfigFile, bool, error) {
	configPath, matched, commandlineErr := findConfigPath(ctx, integration, reader, findConfigArg)
	if configPath != "" {
		file, err := reader.ReadFile(ctx, configPath)
		if err != nil {
			return configfilesdiscoveryimpl.ConfigFile{}, false, fmt.Errorf("read explicit config file %q: %w", configPath, err)
		}
		return file, true, nil
	}
	if matched {
		log.Debugf("config files discovery skipped default paths for integration %q because an explicit config argument was found but no unique path could be resolved", integration)
		return configfilesdiscoveryimpl.ConfigFile{}, false, commandlineErr
	}

	log.Debugf("config files discovery found no explicit config path for integration %q; checking %d default paths", integration, len(defaultPaths))
	files := make([]configfilesdiscoveryimpl.ConfigFile, 0, len(defaultPaths))
	readablePaths := make([]string, 0, len(defaultPaths))
	for _, path := range defaultPaths {
		file, err := reader.ReadFile(ctx, path)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return configfilesdiscoveryimpl.ConfigFile{}, false, ctxErr
			}
			log.Debugf("config files discovery could not read default config file for integration %q at path %q: %v", integration, path, err)
			continue
		}
		files = append(files, file)
		readablePaths = append(readablePaths, path)
	}

	switch len(files) {
	case 0:
		log.Debugf("config files discovery found no readable default config file for integration %q", integration)
		return configfilesdiscoveryimpl.ConfigFile{}, false, commandlineErr
	case 1:
		log.Debugf("config files discovery selected default config file for integration %q at path %q", integration, readablePaths[0])
		return files[0], true, nil
	default:
		log.Debugf("config files discovery skipped ambiguous default config files for integration %q: %v", integration, readablePaths)
		return configfilesdiscoveryimpl.ConfigFile{}, false, nil
	}
}
