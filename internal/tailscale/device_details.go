package tailscale

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"

	"github.com/crypt0rr/tailstate/internal/model"
)

func (c *Client) deviceDetails(ctx context.Context) ([]model.Resource, error) {
	detailCtx, cancel := context.WithTimeout(ctx, deviceDetailsPollTimeout)
	defer cancel()
	devices, ok := c.cachedDevices()
	if !ok {
		var err error
		devices, err = c.allPages(detailCtx, c.tailnet("devices?fields=all"), "devices")
		if err != nil {
			return nil, err
		}
		c.cacheDeviceMaps(devices)
	}
	return c.deviceDetailsFromDevices(detailCtx, devices)
}

func (c *Client) deviceDetailsFromDevices(ctx context.Context, devices []map[string]any) ([]model.Resource, error) {
	type detailJob struct {
		index  int
		device map[string]any
	}
	type detailResult struct {
		index    int
		resource model.Resource
		err      error
		hasValue bool
	}
	if len(devices) == 0 {
		return nil, nil
	}
	detailCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	limits := c.collectionLimitsOrDefault()
	var budgetMu sync.Mutex
	var aggregateBytes int64
	var aggregateErr error
	accountResponse := func(responseBytes int64) error {
		budgetMu.Lock()
		defer budgetMu.Unlock()
		if aggregateErr != nil {
			return aggregateErr
		}
		if responseBytes > limits.MaxBytes-aggregateBytes {
			aggregateErr = fmt.Errorf("device_details collection exceeds aggregate response limit of %d bytes", limits.MaxBytes)
			cancel()
			return aggregateErr
		}
		aggregateBytes += responseBytes
		return nil
	}
	order := c.deviceDetailOrder(devices)
	jobs := make(chan detailJob)
	workers := min(deviceDetailWorkers, len(devices))
	results := make(chan detailResult, max(1, workers))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				id := idFor(job.device, []string{"id", "nodeId", "nodeID"})
				if id == "" {
					results <- detailResult{index: job.index, err: errors.New("device detail response omitted device id")}
					continue
				}
				combined := map[string]any{}
				var detailErr error
				// Routes are not fetched here: devices?fields=all already returns
				// advertisedRoutes and enabledRoutes, so a routes sub-request
				// would only report every route change a second time.
				for _, detail := range []struct {
					key  string
					path string
				}{
					{key: "postureAttributes", path: "attributes"},
					{key: "deviceInvites", path: "device-invites"},
				} {
					key, path := detail.key, detail.path
					value, responseBytes, err := c.getWithBytes(detailCtx, c.global("device/"+url.PathEscape(id)+"/"+path))
					if err != nil {
						budgetMu.Lock()
						budgetErr := aggregateErr
						budgetMu.Unlock()
						if budgetErr != nil {
							detailErr = budgetErr
							break
						}
						// A missing per-device detail endpoint is an incomplete
						// response, not proof that the whole subresource is
						// unsupported. Preserve that distinction so the monitor does
						// not persist a synthetic "unsupported" value or clear a
						// previously known detail snapshot.
						var httpErr *HTTPError
						if errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound {
							detailErr = err
							break
						}
						if IsUnsupported(err) {
							combined[key] = map[string]any{"unsupported": true}
							continue
						}
						detailErr = err
						break
					}
					if budgetErr := accountResponse(responseBytes); budgetErr != nil {
						detailErr = budgetErr
						break
					}
					combined[key] = value
				}
				if detailErr != nil {
					results <- detailResult{index: job.index, err: detailErr}
					continue
				}
				results <- detailResult{index: job.index, hasValue: true, resource: model.Resource{ID: id, Type: "device_details", Name: nameFor(job.device, id), Collector: "device_details", Data: combined}}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, index := range order {
			select {
			case jobs <- detailJob{index: index, device: devices[index]}:
			case <-detailCtx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	ordered := make([]detailResult, 0, len(devices))
	completed := make([]int, 0, len(devices))
	var partialErr error
	for result := range results {
		if result.err != nil {
			// A request cancelled by the poll deadline was not really attempted;
			// leave it at the front of the next poll's refresh order.
			if ctx.Err() == nil {
				completed = append(completed, result.index)
			}
			if partialErr == nil {
				partialErr = result.err
			}
			continue
		}
		if result.hasValue {
			completed = append(completed, result.index)
			ordered = append(ordered, result)
		}
	}
	budgetMu.Lock()
	budgetErr := aggregateErr
	budgetMu.Unlock()
	if budgetErr != nil {
		return nil, budgetErr
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].index < ordered[j].index })
	out := make([]model.Resource, 0, len(ordered))
	for _, result := range ordered {
		out = append(out, result.resource)
	}
	c.recordDeviceDetailAttempts(devices, completed)
	// Count every device missing from the result, including devices that were
	// never dispatched because the deadline expired. A deadline must never look
	// like a complete response.
	if missing := len(devices) - len(out); missing > 0 {
		if partialErr == nil {
			cause := ctx.Err()
			if cause == nil {
				cause = errors.New("device detail results were incomplete")
			}
			partialErr = fmt.Errorf("device_details refreshed %d of %d devices before the poll deadline: %w", len(out), len(devices), cause)
		}
		return out, &PartialError{Err: partialErr, Count: missing}
	}
	return out, nil
}

// deviceDetailOrder returns device indexes ordered stalest-first: devices
// whose detail requests have never completed come first, then the ones that
// completed longest ago. Ties keep the API list order. A poll that hits its
// deadline therefore resumes with the devices it could not reach instead of
// starving the same tail of the list on every poll.
func (c *Client) deviceDetailOrder(devices []map[string]any) []int {
	order := make([]int, len(devices))
	attempts := make([]int64, len(devices))
	c.detailMu.Lock()
	for index, device := range devices {
		order[index] = index
		attempts[index] = c.detailAttempt[idFor(device, []string{"id", "nodeId", "nodeID"})]
	}
	c.detailMu.Unlock()
	sort.SliceStable(order, func(i, j int) bool { return attempts[order[i]] < attempts[order[j]] })
	return order
}

// recordDeviceDetailAttempts marks the supplied device indexes as refreshed
// in a new poll sequence and forgets devices that are no longer listed.
func (c *Client) recordDeviceDetailAttempts(devices []map[string]any, completed []int) {
	c.detailMu.Lock()
	defer c.detailMu.Unlock()
	c.detailPoll++
	next := make(map[string]int64, len(devices))
	for _, device := range devices {
		id := idFor(device, []string{"id", "nodeId", "nodeID"})
		if previous, ok := c.detailAttempt[id]; ok && id != "" {
			next[id] = previous
		}
	}
	for _, index := range completed {
		if id := idFor(devices[index], []string{"id", "nodeId", "nodeID"}); id != "" {
			next[id] = c.detailPoll
		}
	}
	c.detailAttempt = next
}

func (c *Client) cacheDeviceResources(resources []model.Resource) {
	devices := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		if data, ok := resource.Data.(map[string]any); ok {
			devices = append(devices, data)
		}
	}
	c.cacheDeviceMaps(devices)
}

func (c *Client) cacheDeviceMaps(devices []map[string]any) {
	copyOf := append([]map[string]any(nil), devices...)
	c.deviceCacheMu.Lock()
	c.deviceCache = copyOf
	c.deviceCacheMu.Unlock()
}

func (c *Client) cachedDevices() ([]map[string]any, bool) {
	c.deviceCacheMu.RLock()
	defer c.deviceCacheMu.RUnlock()
	if c.deviceCache == nil {
		return nil, false
	}
	return append([]map[string]any(nil), c.deviceCache...), true
}

func (c *Client) clearDeviceCache() {
	c.deviceCacheMu.Lock()
	c.deviceCache = nil
	c.deviceCacheMu.Unlock()
}
