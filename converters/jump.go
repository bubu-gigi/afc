package converters

import "afc/config"

func ConvertJumpToCsv(files []string, config *config.Config) {
	for _, file := range files {
		convertJump(file, config)
	}
}

func convertJump(file string, config *config.Config) {

}