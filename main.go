//go:build arm64

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	cli "github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

// main.go 仅保留CLI入口，核心逻辑下沉到各模块。

func main() {
	// log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	app := &cli.App{
		Name:  "dexdump",
		Usage: "Dump in-memory DEX and method bytecode or fix dumped DEX files",
		// 自定义帮助模板：精简顶层信息并展示子命令详情
		CustomAppHelpTemplate: `NAME:
   {{.Name}} - {{.Usage}}

USAGE:
   {{.HelpName}} [command] [options]

COMMANDS:
{{range .VisibleCommands}}   {{index .Names 0}}  {{.Usage}}
{{end}}

SUBCOMMANDS:
{{range .VisibleCommands}}
{{.Name}} - {{.Usage}}
  Usage: {{$.HelpName}} {{.Name}} [options]
  Description: {{.Description}}
  Options:
   {{range .VisibleFlags}}{{.}}
   {{end}}

{{end}}`,
		HideHelpCommand: true,
		Commands: []*cli.Command{
			{
				Name:        "dump",
				Usage:       "Start DEX dumper",
				Description: "Attach probes to libart and stream DEX/method events; provide either --uid or --name to filter.",
				CustomHelpTemplate: `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.HelpName}} [command options]

DESCRIPTION:
   {{.Description}}

OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}`,
				Flags: []cli.Flag{
					&cli.Uint64Flag{Name: "uid", Aliases: []string{"u"}, Usage: "Filter by UID (alternative to --name)"},
					&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "Android package name to derive UID (alternative to --uid)"},
					&cli.StringFlag{Name: "libart", Aliases: []string{"l"}, Usage: "Path to libart.so (target device)", Value: "/apex/com.android.art/lib64/libart.so", DefaultText: "/apex/com.android.art/lib64/libart.so"},
					&cli.StringFlag{Name: "out", Aliases: []string{"o", "output"}, Usage: "Output directory on device", Value: "/data/local/tmp/dex_out", DefaultText: "/data/local/tmp/dex_out"},
					&cli.BoolFlag{Name: "trace", Aliases: []string{"t"}, Usage: "Print executed methods in real time during dumping"},
					&cli.BoolFlag{Name: "clean-oat", Aliases: []string{"c"}, Usage: "Remove /data/app/.../oat folders of target app(s) before dumping", Value: true},
					&cli.BoolFlag{Name: "auto-fix", Aliases: []string{"f"}, Usage: "Automatically fix DEX files after dumping", Value: true},
					&cli.BoolFlag{Name: "no-clean-oat", Usage: "Disable automatic oat cleaning"},
					&cli.BoolFlag{Name: "no-auto-fix", Usage: "Disable automatic DEX fixing"},
					&cli.Uint64Flag{Name: "execute-offset", Usage: "Manual offset for art::interpreter::Execute function (hex value, e.g. 0x12345)"},
					&cli.Uint64Flag{Name: "nterp-offset", Usage: "Manual offset for ExecuteNterpImpl function (hex value, e.g. 0x12345)"},
					&cli.BoolFlag{Name: "auto-stop", Usage: "Stop automatically when target process exits", Value: true},
					&cli.BoolFlag{Name: "no-auto-stop", Usage: "Disable automatic stop on target exit"},
				},
				Action: func(c *cli.Context) error {
					fmt.Println("提示：本文件仅供学习参考请24小时内删除，编译人@rc4aes和testing,来自爱国人士交流群")

					uid := uint32(c.Uint64("uid"))
					pkgName := c.String("name")
					libArtPath := c.String("libart")
					outputDir := c.String("out")
					trace := c.Bool("trace")
					cleanOat := c.Bool("clean-oat") && !c.Bool("no-clean-oat")
					autoFix := c.Bool("auto-fix") && !c.Bool("no-auto-fix")
					executeOffset := c.Uint64("execute-offset")
					nterpOffset := c.Uint64("nterp-offset")
					autoStop := c.Bool("auto-stop") && !c.Bool("no-auto-stop")

					// 预先创建输出目录，避免后续写文件失败
					if err := os.MkdirAll(outputDir, 0755); err != nil {
						return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
					}

					if uid == 0 && pkgName == "" {
						return fmt.Errorf("either --uid or --name must be provided")
					}
					if uid == 0 && pkgName != "" {
						// 通过包名解析UID，避免用户手动查找
						resolved, err := LookupUIDByPackageName(pkgName)
						if err != nil {
							return err
						}
						uid = resolved
						log.Printf("[+] Resolved UID %d from package %q", uid, pkgName)
					}

					// 可选：删除OAT目录提升DEX结构完整性
					if cleanOat {
						if pkgName != "" {
							RemoveOatDirsForPackage(pkgName)
						} else if uid != 0 {
							RemoveOatDirsByUID(uid)
						}
					}

					// 创建并启动DexDumper
					dumper := NewDexDumper(libArtPath, uid, outputDir, trace, autoFix, executeOffset, nterpOffset)

					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					if autoStop && uid != 0 {
						go func() {
							ticker := time.NewTicker(1 * time.Second)
							defer ticker.Stop()
							for {
								select {
								case <-ctx.Done():
									return
								case <-ticker.C:
									running, err := IsUIDRunning(uid)
									if err != nil {
										log.Printf("[auto-stop] failed to check uid %d: %v", uid, err)
										continue
									}
									if !running {
										log.Printf("[auto-stop] target uid %d exited, stopping...", uid)
										cancel()
										return
									}
								}
							}
						}()
					}

					sigChan := make(chan os.Signal, 1)
					signal.Notify(sigChan, os.Interrupt, unix.SIGTERM, unix.SIGHUP, unix.SIGQUIT)
					defer signal.Stop(sigChan)

					go func() {
						for {
							select {
							case sig := <-sigChan:
								// 收到信号后主动触发Stop流程
								log.Printf("Received signal %v, flushing JSON and shutting down...", sig)
								cancel()
								return
							case <-ctx.Done():
								return
							}
						}
					}()

					// 启动并阻塞等待退出
					if err := dumper.Start(ctx); err != nil {
						return fmt.Errorf("failed to start dumper: %w", err)
					}
					if err := dumper.Stop(); err != nil {
						log.Printf("Failed to stop dumper cleanly: %v", err)
					}
					log.Println("dexdump finished")
					return nil
				},
			},
			{
				Name:        "fix",
				Usage:       "Fix dumped DEX files in a directory",
				Description: "Scan a directory for dumped DEX files and fix headers/structures for readability.",
				CustomHelpTemplate: `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.HelpName}} [command options]

DESCRIPTION:
   {{.Description}}

OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}`,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "dir", Aliases: []string{"d"}, Usage: "Directory containing dumped DEX files", Required: true},
				},
				Action: func(c *cli.Context) error {
					outDir := c.String("dir")
					if err := FixDexDirectory(outDir); err != nil {
						return fmt.Errorf("fix dex failed: %w", err)
					}
					log.Printf("Fix completed for directory: %s", outDir)
					return nil
				},
			},
		},
		Action: func(c *cli.Context) error {
			// 默认显示帮助，避免误操作
			return cli.ShowAppHelp(c)
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
