package collector

import (
	"context"
	"encoding/json"
)

type kubeService struct {
	Meta objectMeta `json:"metadata"`
	Spec struct {
		Type            string            `json:"type"`
		Selector        map[string]string `json:"selector"`
		PublishNotReady bool              `json:"publishNotReadyAddresses"`
		Ports           []struct {
			Name     string `json:"name"`
			Port     int32  `json:"port"`
			Protocol string `json:"protocol"`
			NodePort int32  `json:"nodePort"`
		} `json:"ports"`
	} `json:"spec"`
}

func serviceKey(namespace, name string) string { return namespace + "/" + name }

type kubeEndpointSlice struct {
	Meta        objectMeta `json:"metadata"`
	AddressType string     `json:"addressType"`
	Endpoints   []struct {
		Addresses  []string `json:"addresses"`
		Conditions struct {
			Ready       *bool `json:"ready"`
			Serving     *bool `json:"serving"`
			Terminating *bool `json:"terminating"`
		} `json:"conditions"`
		Target struct {
			Kind string `json:"kind"`
			UID  string `json:"uid"`
		} `json:"targetRef"`
	} `json:"endpoints"`
}

type backendSet struct {
	ready     map[string]bool
	uncertain map[string]bool
}

func (k *kubeConnection) collectServices(ctx context.Context) ([]Row, error) {
	var services []kubeService
	byName := make(map[string]int)
	keys := make(map[string]bool)
	err := k.list(ctx, kubePaths["services"], func(raw json.RawMessage) error {
		var item kubeService
		if json.Unmarshal(raw, &item) != nil || item.Meta.UID == "" || item.Meta.Name == "" || item.Meta.Namespace == "" {
			return fail("invalid_response")
		}
		qualified := serviceKey(item.Meta.Namespace, item.Meta.Name)
		if _, seen := byName[qualified]; seen || keys[item.Meta.UID] {
			return fail("invalid_response")
		}
		byName[qualified] = len(services)
		keys[item.Meta.UID] = true
		services = append(services, item)
		return nil
	}, func() {
		services = nil
		clear(byName)
		clear(keys)
	})
	if err != nil {
		return nil, err
	}
	byUID := make(map[string]*backendSet)
	for _, service := range services {
		if service.Spec.Type != "ExternalName" && len(service.Spec.Selector) != 0 {
			byUID[service.Meta.UID] = &backendSet{ready: make(map[string]bool), uncertain: make(map[string]bool)}
		}
	}
	var slicesErr error
	if len(byUID) > 0 {
		slicesErr = k.list(ctx, kubePaths["endpoint_slices"], func(raw json.RawMessage) error {
			var item kubeEndpointSlice
			if json.Unmarshal(raw, &item) != nil || item.Meta.Name == "" || item.Meta.Namespace == "" {
				return fail("invalid_response")
			}
			pos, ok := byName[serviceKey(item.Meta.Namespace, item.Meta.Labels["kubernetes.io/service-name"])]
			if !ok {
				return nil
			}
			service := services[pos]
			set := byUID[service.Meta.UID]
			if set == nil {
				return nil
			}
			for _, owner := range item.Meta.Owners {
				if owner.Kind == "Service" && owner.UID != service.Meta.UID {
					return nil
				}
			}
			for _, endpoint := range item.Endpoints {
				if endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
					continue
				}
				dest := set.ready
				if service.Spec.PublishNotReady {
					if endpoint.Conditions.Serving == nil {
						dest = set.uncertain
					} else if !*endpoint.Conditions.Serving {
						continue
					}
				} else if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
					continue
				}
				if endpoint.Target.Kind == "Pod" && endpoint.Target.UID != "" {
					dest["pod:"+endpoint.Target.UID] = true
				} else {
					for _, addr := range endpoint.Addresses {
						if addr != "" {
							dest[item.AddressType+":"+addr] = true
						}
					}
				}
			}
			return nil
		}, func() {
			for _, set := range byUID {
				clear(set.ready)
				clear(set.uncertain)
			}
		})
	}
	rows := make([]Row, 0, len(services))
	for _, service := range services {
		var ready *int
		state := "not_applicable"
		set := byUID[service.Meta.UID]
		if set != nil {
			switch Code(slicesErr) {
			case "not_found":
				state = "unsupported"
			case "":
				state = "ok"
				for candidate := range set.uncertain {
					if !set.ready[candidate] {
						state = "unknown"
						break
					}
				}
				if state == "ok" {
					count := len(set.ready)
					ready = &count
				}
			default:
				state = "unreadable"
			}
		}
		v := metadataRow(service.Meta)
		v["type"], v["ports"] = service.Spec.Type, service.Spec.Ports
		v["ready_backends"], v["backends_state"] = ready, state
		if state == "unreadable" {
			v["backends_error"] = Code(slicesErr)
		}
		rows, err = appendRow(rows, service.Meta.UID, v)
		if err != nil {
			return nil, err
		}
	}
	return rows, nil
}
