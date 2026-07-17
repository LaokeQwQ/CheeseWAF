package cli

import (
	"fmt"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli/clilang"
	"github.com/spf13/cobra"
)

func newLangCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lang",
		Short: clilang.T("lang.short"),
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: clilang.T("lang.show.short"),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), clilang.T("lang.current", clilang.Current()))
			fmt.Fprintln(cmd.OutOrStdout(), clilang.T("lang.supported", strings.Join(clilang.Supported(), ", ")))
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "set [en|zh-CN]",
		Short: clilang.T("lang.set.short"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := clilang.Set(args[0], dataDir); err != nil {
				return err
			}
			path := dataDir
			if path == "" {
				path = "./data"
			}
			fmt.Fprintln(cmd.OutOrStdout(), clilang.T("lang.saved", clilang.Current(), path))
			return nil
		},
	})
	cmd.Run = func(cmd *cobra.Command, args []string) {
		// Default to show when no subcommand.
		fmt.Fprintln(cmd.OutOrStdout(), clilang.T("lang.current", clilang.Current()))
		fmt.Fprintln(cmd.OutOrStdout(), clilang.T("lang.supported", strings.Join(clilang.Supported(), ", ")))
		fmt.Fprintln(cmd.OutOrStdout(), clilang.T("lang.usage"))
	}
	return cmd
}
