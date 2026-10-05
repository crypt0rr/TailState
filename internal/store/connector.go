package store

import (
	"context"
	"database/sql/driver"
	"strconv"
	"sync/atomic"

	"modernc.org/sqlite"
)

// pageLimitedConnector opens SQLite connections through a private driver
// instance whose connection hook applies PRAGMA max_page_count. The pragma is
// a per-connection pager setting that SQLite does not persist in the database
// file. database/sql discards a connection after an interrupted statement (a
// context deadline or cancellation), and the replacement connection would
// otherwise start with SQLite's default ceiling, silently disabling the
// configured storage budget.
type pageLimitedConnector struct {
	dsn      string
	driver   *sqlite.Driver
	maxPages atomic.Int64
}

func newPageLimitedConnector(dsn string) *pageLimitedConnector {
	connector := &pageLimitedConnector{dsn: dsn, driver: &sqlite.Driver{}}
	connector.driver.RegisterConnectionHook(func(conn sqlite.ExecQuerierContext, _ string) error {
		pages := connector.maxPages.Load()
		if pages < 1 {
			return nil
		}
		_, err := conn.ExecContext(context.Background(), "PRAGMA max_page_count = "+strconv.FormatInt(pages, 10), nil)
		return err
	})
	return connector
}

func (c *pageLimitedConnector) Connect(context.Context) (driver.Conn, error) {
	return c.driver.Open(c.dsn)
}

func (c *pageLimitedConnector) Driver() driver.Driver { return c.driver }
