package cgroup

// TODO: Implement IO stats later.
//func statIOV2(dirPath string, stats *Stats) error {
//	const file = "io.stat"
//	values, err := readCgroup2MapFile(dirPath, file)
//	if err != nil {
//		return err
//	}
//	// more details on the io.stat file format: https://www.kernel.org/doc/Documentation/cgroup-v2.txt
//	var parsedStats BlkioStats
//	for k, v := range values {
//		d := strings.Split(k, ":")
//		if len(d) != 2 {
//			continue
//		}
//		major, err := strconv.ParseUint(d[0], 10, 64)
//		if err != nil {
//			return &parseError{Path: dirPath, File: file, Err: err}
//		}
//		minor, err := strconv.ParseUint(d[1], 10, 64)
//		if err != nil {
//			return &parseError{Path: dirPath, File: file, Err: err}
//		}
//
//		for _, item := range v {
//			d := strings.Split(item, "=")
//			if len(d) != 2 {
//				continue
//			}
//			op := d[0]
//
//			// Map to the cgroupv1 naming and layout (in separate tables).
//			var targetTable *[]BlkioStatEntry
//			switch op {
//			// Equivalent to cgroupv1's blkio.io_service_bytes.
//			case "rbytes":
//				op = "Read"
//				targetTable = &parsedStats.IoServiceBytesRecursive
//			case "wbytes":
//				op = "Write"
//				targetTable = &parsedStats.IoServiceBytesRecursive
//			// Equivalent to cgroupv1's blkio.io_serviced.
//			case "rios":
//				op = "Read"
//				targetTable = &parsedStats.IoServicedRecursive
//			case "wios":
//				op = "Write"
//				targetTable = &parsedStats.IoServicedRecursive
//			default:
//				// Skip over entries we cannot map to cgroupv1 stats for now.
//				// In the future we should expand the stats struct to include
//				// them.
//				logrus.Debugf("cgroupv2 io stats: skipping over unmappable %s entry", item)
//				continue
//			}
//
//			value, err := strconv.ParseUint(d[1], 10, 64)
//			if err != nil {
//				return &parseError{Path: dirPath, File: file, Err: err}
//			}
//
//			entry := BlkioStatEntry{
//				Op:    op,
//				Major: major,
//				Minor: minor,
//				Value: value,
//			}
//			*targetTable = append(*targetTable, entry)
//		}
//	}
//	stats.BlkioStats = parsedStats
//	return nil
//}
//
//func readCgroup2MapFile(dirPath string, name string) (map[string][]string, error) {
//	ret := map[string][]string{}
//	f, err := cgroups.OpenFile(dirPath, name, os.O_RDONLY)
//	if err != nil {
//		return nil, err
//	}
//	defer f.Close()
//	scanner := bufio.NewScanner(f)
//	for scanner.Scan() {
//		line := scanner.Text()
//		parts := strings.Fields(line)
//		if len(parts) < 2 {
//			continue
//		}
//		ret[parts[0]] = parts[1:]
//	}
//	if err := scanner.Err(); err != nil {
//		return nil, &parseError{Path: dirPath, File: name, Err: err}
//	}
//	return ret, nil
//}
