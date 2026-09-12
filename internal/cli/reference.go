package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Southclaws/oauthcli/internal/cligen"
	"github.com/Southclaws/oauthcli/rfcs"
)

// reference prints an embedded specification, one section of it, or the
// list of specifications available.
func reference(ctx context.Context, cmd *cobra.Command, commandIO cligen.IO, p cligen.ReferenceParams) (cligen.ReferenceList, error) {
	streams := newOutput(cmd, commandIO)
	format := string(p.Format)

	if p.Spec == "" {
		list := make(cligen.ReferenceList, 0, len(rfcs.Specs))
		rows := make([][]string, 0, len(rfcs.Specs))
		for i := range rfcs.Specs {
			spec := &rfcs.Specs[i]
			list = append(list, cligen.Reference{ID: spec.ID, Title: spec.Title, File: spec.File, URL: spec.URL, Bytes: rfcs.Size(spec)})
			rows = append(rows, []string{spec.ID, spec.Title, spec.File})
		}
		switch format {
		case "json", "yaml":
		case "plain":
			streams.Out.Plain(rows)
		default:
			streams.Out.Title("Embedded specifications", fmt.Sprintf("%d documents; oauthcli reference <id> [--section N]", len(rows)))
			streams.Out.Table([]string{"ID", "TITLE", "FILE"}, rows)
		}
		return list, nil
	}

	spec, err := rfcs.Find(p.Spec)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	text, err := rfcs.Text(spec)
	if err != nil {
		return nil, err
	}
	entry := cligen.Reference{ID: spec.ID, Title: spec.Title, File: spec.File, URL: spec.URL, Bytes: len(text)}
	if p.Section != "" {
		section, err := rfcs.Section(text, p.Section)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrNotFound, spec.ID, err)
		}
		text = section
		entry.Section = &p.Section
	}
	entry.Text = &text

	switch format {
	case "json", "yaml":
	default:
		fmt.Fprint(streams.Out.Raw(), text)
	}
	return cligen.ReferenceList{entry}, nil
}
