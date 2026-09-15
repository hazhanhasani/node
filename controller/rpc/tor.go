package rpc

import (
	"context"
	"time"

	tormgr "github.com/pasarguard/node/backend/tor"
	"github.com/pasarguard/node/common"
)

func unixTime(value *time.Time) int64 {
	if value == nil {
		return 0
	}
	return value.Unix()
}

func torLocationResponse(loc tormgr.Location) *common.TorLocation {
	return &common.TorLocation{
		Id:                  loc.ID,
		Slug:                loc.Slug,
		DisplayName:         loc.DisplayName,
		CountryCode:         loc.CountryCode,
		Enabled:             loc.Enabled,
		SubscriptionEnabled: loc.SubscriptionEnabled,
		SortOrder:           loc.SortOrder,
		BaseInboundTag:      loc.BaseInboundTag,
		XrayInboundPort:     uint32(loc.XrayInboundPort),
		XrayInboundTag:      loc.XrayInboundTag,
		XrayOutboundTag:     loc.XrayOutboundTag,
		XrayRuleTag:         loc.XrayRuleTag,
		TorSocksPort:        uint32(loc.TorSocksPort),
		TorControlPort:      uint32(loc.TorControlPort),
		TorDataDirectory:    loc.TorDataDirectory,
		DesiredCountry:      loc.DesiredCountry,
		DetectedCountry:     loc.DetectedCountry,
		DetectedExitIp:      loc.DetectedExitIP,
		HealthStatus:        string(loc.HealthStatus),
		LatencyMs:           loc.LatencyMS,
		ProcessStatus:       string(loc.ProcessStatus),
		LastCheckedAt:       unixTime(loc.LastCheckedAt),
		LastHealthyAt:       unixTime(loc.LastHealthyAt),
		LastError:           loc.LastError,
		AutoRepair:          loc.AutoRepair,
		RestartAttempts:     int32(loc.RestartAttempts),
		CreatedAt:           loc.CreatedAt.Unix(),
		UpdatedAt:           loc.UpdatedAt.Unix(),
	}
}

func torSpec(req *common.TorLocationSpec) tormgr.Spec {
	return tormgr.Spec{
		ID:                  req.GetId(),
		Slug:                req.GetSlug(),
		DisplayName:         req.GetDisplayName(),
		CountryCode:         req.GetCountryCode(),
		Enabled:             req.GetEnabled(),
		SubscriptionEnabled: req.GetSubscriptionEnabled(),
		SortOrder:           req.GetSortOrder(),
		BaseInboundTag:      req.GetBaseInboundTag(),
		XrayInboundPort:     int(req.GetXrayInboundPort()),
		XrayInboundTag:      req.GetXrayInboundTag(),
		XrayOutboundTag:     req.GetXrayOutboundTag(),
		XrayRuleTag:         req.GetXrayRuleTag(),
		TorSocksPort:        int(req.GetTorSocksPort()),
		TorControlPort:      int(req.GetTorControlPort()),
		AutoRepair:          req.GetAutoRepair(),
	}
}

func torLocationsResponse(locations []tormgr.Location) *common.TorLocationsResponse {
	out := &common.TorLocationsResponse{Locations: make([]*common.TorLocation, 0, len(locations))}
	for _, loc := range locations {
		out.Locations = append(out.Locations, torLocationResponse(loc))
	}
	return out
}

func (s *Service) ListTorLocations(_ context.Context, _ *common.Empty) (*common.TorLocationsResponse, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	return torLocationsResponse(manager.List()), nil
}

func (s *Service) GetTorLocation(_ context.Context, req *common.TorLocationIDRequest) (*common.TorLocation, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	loc, err := manager.Get(req.GetId())
	if err != nil {
		return nil, err
	}
	return torLocationResponse(loc), nil
}

func (s *Service) CreateTorLocation(ctx context.Context, req *common.TorLocationSpec) (*common.TorLocation, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	loc, err := manager.CreateOrUpdate(ctx, torSpec(req))
	if err != nil {
		return torLocationResponse(loc), err
	}
	return torLocationResponse(loc), nil
}

func (s *Service) UpdateTorLocation(ctx context.Context, req *common.TorLocationSpec) (*common.TorLocation, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	if _, err := manager.Get(req.GetId()); err != nil {
		return nil, err
	}
	loc, err := manager.CreateOrUpdate(ctx, torSpec(req))
	if err != nil {
		return torLocationResponse(loc), err
	}
	return torLocationResponse(loc), nil
}

func (s *Service) DeleteTorLocation(ctx context.Context, req *common.DeleteTorLocationRequest) (*common.Empty, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	if err := manager.Delete(ctx, req.GetId(), req.GetPurgeData()); err != nil {
		return nil, err
	}
	return &common.Empty{}, nil
}

func (s *Service) EnableTorLocation(ctx context.Context, req *common.TorLocationIDRequest) (*common.TorLocation, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	loc, err := manager.Enable(ctx, req.GetId(), true)
	if err != nil {
		return torLocationResponse(loc), err
	}
	return torLocationResponse(loc), nil
}

func (s *Service) DisableTorLocation(ctx context.Context, req *common.TorLocationIDRequest) (*common.TorLocation, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	loc, err := manager.Enable(ctx, req.GetId(), false)
	if err != nil {
		return torLocationResponse(loc), err
	}
	return torLocationResponse(loc), nil
}

func (s *Service) RestartTorLocation(ctx context.Context, req *common.TorLocationIDRequest) (*common.TorLocation, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	loc, err := manager.Restart(ctx, req.GetId())
	if err != nil {
		return torLocationResponse(loc), err
	}
	return torLocationResponse(loc), nil
}

func (s *Service) NewTorIdentity(ctx context.Context, req *common.TorLocationIDRequest) (*common.TorLocation, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	loc, err := manager.NewIdentity(ctx, req.GetId())
	if err != nil {
		return torLocationResponse(loc), err
	}
	return torLocationResponse(loc), nil
}

func (s *Service) GetTorHealth(ctx context.Context, req *common.TorLocationIDRequest) (*common.TorLocation, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	loc, err := manager.HealthCheck(ctx, req.GetId())
	if err != nil {
		return torLocationResponse(loc), err
	}
	return torLocationResponse(loc), nil
}

func (s *Service) RepairTorLocation(ctx context.Context, req *common.TorLocationIDRequest) (*common.TorLocation, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	loc, err := manager.Repair(ctx, req.GetId(), true)
	if err != nil {
		return torLocationResponse(loc), err
	}
	return torLocationResponse(loc), nil
}

func (s *Service) TestTorLocation(ctx context.Context, req *common.TorLocationIDRequest) (*common.TorLocation, error) {
	return s.GetTorHealth(ctx, req)
}

func (s *Service) ForceReconcileTor(ctx context.Context, _ *common.Empty) (*common.TorReconcileResponse, error) {
	manager, err := s.TorManager()
	if err != nil {
		return nil, err
	}
	if err := manager.Reconcile(ctx); err != nil {
		return &common.TorReconcileResponse{Locations: torLocationsResponse(manager.List()).Locations}, err
	}
	return &common.TorReconcileResponse{Locations: torLocationsResponse(manager.List()).Locations}, nil
}
