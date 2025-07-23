package internal

import (
    "fmt"
    "path/filepath"
    "strings"
)

func ValidateCommand(command string, args []string, projectRoot string) error {
    // 检查目录切换命令
    switch command {
    case "cd", "pushd", "popd":
        if len(args) > 0 {
            targetDir := args[0]
            absDir, err := filepath.Abs(filepath.Join(projectRoot, targetDir))
            if err != nil {
                return fmt.Errorf("invalid path: %v", err)
            }
            if !strings.HasPrefix(absDir, projectRoot) {
                return fmt.Errorf("access to external directory denied")
            }
        }
    }

    // 检查所有参数是否包含外部路径
    for _, arg := range args {
        if filepath.IsAbs(arg) {
            if !strings.HasPrefix(arg, projectRoot) {
                return fmt.Errorf("absolute path outside project root denied: %s", arg)
            }
        } else if strings.Contains(arg, "..") {
            absPath, err := filepath.Abs(filepath.Join(projectRoot, arg))
            if err != nil {
                return fmt.Errorf("invalid path: %v", err)
            }
            if !strings.HasPrefix(absPath, projectRoot) {
                return fmt.Errorf("relative path outside project root denied: %s", arg)
            }
        }
    }

    return nil
}