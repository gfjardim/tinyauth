package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/apis/tinyauth/v1alpha1"
	"go.uber.org/dig"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type watchedResource struct {
	gvr schema.GroupVersionResource
	typ ResourceType
}

func (w watchedResource) pretty() string {
	return w.gvr.Group + "/" + w.gvr.Version + "/" + w.gvr.Resource
}

func ensureResourceMeta(meta *ResourceMeta) bool {
	return meta.Name != "" && meta.Namespace != ""
}

type ResourceMeta struct {
	Typ       ResourceType
	Name      string
	Namespace string
}

type ExtractionResult struct {
	Meta *ResourceMeta
	Apps map[string]model.App
}

type ResourceType string

const (
	ResourceTypeIngress ResourceType = "ingress"
	ResourceTypeCRD     ResourceType = "crd"
)

var supportedResources = []watchedResource{
	{
		gvr: schema.GroupVersionResource{
			Group:    "networking.k8s.io",
			Version:  "v1",
			Resource: "ingresses",
		},
		typ: ResourceTypeIngress,
	},
	{
		gvr: schema.GroupVersionResource{
			Group:    "tinyauth.app",
			Version:  "v1alpha1",
			Resource: "applications",
		},
		typ: ResourceTypeCRD,
	},
}

type typedItem struct {
	typ     ResourceType
	ingress *networking.Ingress
	crd     *v1alpha1.Application
}

func convertFromUnstructured[T any](obj *unstructured.Unstructured) (*T, error) {
	var typed *T
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &typed)
	if err != nil {
		var zero *T
		return zero, fmt.Errorf("failed to convert to typed object: %w", err)
	}
	return typed, nil
}

func (ti *typedItem) fromUnstructured(typ ResourceType, obj *unstructured.Unstructured) (*typedItem, error) {
	switch typ {
	case ResourceTypeIngress:
		typed, err := convertFromUnstructured[networking.Ingress](obj)
		if err != nil {
			return nil, err
		}
		return &typedItem{
			typ:     ResourceTypeIngress,
			ingress: typed,
		}, nil
	case ResourceTypeCRD:
		typed, err := convertFromUnstructured[v1alpha1.Application](obj)
		if err != nil {
			return nil, err
		}
		return &typedItem{
			typ: ResourceTypeCRD,
			crd: typed,
		}, nil
	default:
		return nil, fmt.Errorf("unknown resource type %s", typ)
	}
}

type KubernetesService struct {
	log *logger.Logger
	ctx context.Context

	apps        map[ResourceMeta]map[string]model.App
	client      dynamic.Interface
	typedClient kubernetes.Interface
	mu          sync.RWMutex
	connected   bool

	// first listing of the supported resources: how many are still to come, the
	// error of one that failed, and the channel closed when all are over.
	// The first two are guarded by mu.
	pending int
	syncErr error
	synced  chan struct{}
}

type KubernetesServiceInput struct {
	dig.In

	Log  *logger.Logger
	Ctx  context.Context
	Ding *ding.Ding
}

func NewKubernetesService(i KubernetesServiceInput) (*KubernetesService, error) {
	service := &KubernetesService{
		log:    i.Log,
		apps:   make(map[ResourceMeta]map[string]model.App),
		ctx:    i.Ctx,
		synced: make(chan struct{}),
	}

	cfg, err := service.getConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %w", err)
	}

	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	typedClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create typed kubernetes client: %w", err)
	}

	service.client = client
	service.typedClient = typedClient

	// every supported resource reports once: a watched one when its first
	// listing is over, one that is skipped right away. The count is set
	// before the first watcher starts, so it is complete when one reports.
	service.pending = len(supportedResources)

	watchedGVRs := make(map[string]bool)

	for _, res := range supportedResources {
		ctx, cancel := context.WithTimeout(i.Ctx, 10*time.Second)
		_, err := client.Resource(res.gvr).List(ctx, metav1.ListOptions{Limit: 1})
		cancel()

		if err != nil {
			// The CRD may not be available yet, so we'll fall back to ingress
			i.Log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Failed to access resource, skipping watcher")
			service.firstListingDone(nil)
			continue
		}

		i.Log.App.Debug().Str("res", res.pretty()).Msg("Successfully accessed resource, starting watcher")

		i.Ding.Go(func(ctx context.Context) {
			service.watchGVR(res, ctx)
		}, ding.RingMajor)

		watchedGVRs[res.gvr.Resource] = true
	}

	if len(watchedGVRs) == 0 {
		return nil, fmt.Errorf("failed to access any supported kubernetes api (ingresses, httproutes, grpcroutes)")
	}

	service.connected = true
	i.Log.App.Debug().Msg("Kubernetes label provider started successfully")

	return service, nil
}

func (k *KubernetesService) getConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()

	if err == nil {
		return config, nil
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
}

func (k *KubernetesService) addResource(result ExtractionResult) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.apps[*result.Meta] = result.Apps
}

func (k *KubernetesService) removeResource(meta ResourceMeta) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.apps, meta)
}

func (k *KubernetesService) runLocator(locator func(name string, app *model.App)) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	for _, apps := range k.apps {
		for name, app := range apps {
			locator(name, &app)
		}
	}
}

func (k *KubernetesService) watchedItemChange(res watchedResource, typedItem *typedItem, event watch.EventType) {
	if typedItem == nil {
		k.log.App.Warn().Str("res", res.pretty()).Msg("Resource is nil, skipping")
		return
	}

	var result ExtractionResult

	switch typedItem.typ {
	case ResourceTypeIngress:
		if typedItem.ingress == nil {
			k.log.App.Warn().Str("res", res.pretty()).Msg("Ingress is nil, skipping")
			return
		}
		extractor := NewKubernetesIngressExtractor(KubernetesIngressExtractorInput{
			Log: k.log,
		})
		result = extractor.Extract(typedItem.ingress)
	case ResourceTypeCRD:
		if typedItem.crd == nil {
			k.log.App.Warn().Str("res", res.pretty()).Msg("CRD is nil, skipping")
			return
		}
		extractor := NewKubernetesCRDExtractor(KubernetesCRDInput{
			Log:    k.log,
			Client: k.typedClient,
			Ctx:    k.ctx,
		})
		result = extractor.Extract(typedItem.crd)
	}

	if event == watch.Deleted {
		if result.Meta != nil {
			k.removeResource(*result.Meta)
		}
		return
	}

	if result.Apps == nil {
		k.log.App.Warn().Str("res", res.pretty()).Msg("Failed to extract resource, skipping")
		if result.Meta != nil {
			k.removeResource(*result.Meta)
		}
		return
	}

	k.addResource(result)
}

func (k *KubernetesService) resyncGVR(res watchedResource, ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	list, err := k.client.Resource(res.gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Failed to list resources for resync")
		return err
	}
	seen := make(map[ResourceMeta]any)
	for _, item := range list.Items {
		seen[ResourceMeta{
			Typ:       res.typ,
			Name:      item.GetName(),
			Namespace: item.GetNamespace(),
		}] = struct{}{}
		newTypedItem, err := new(typedItem).fromUnstructured(res.typ, &item)
		if err != nil {
			k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Failed to decode resource, skipping")
			continue
		}
		k.watchedItemChange(res, newTypedItem, watch.Modified)
	}
	k.log.App.Debug().Str("res", res.pretty()).Int("count", len(list.Items)).Msg("Resync complete")
	k.mu.Lock()
	for key := range k.apps {
		if key.Typ != res.typ {
			continue
		}
		if _, ok := seen[key]; !ok {
			delete(k.apps, key)
		}
	}
	k.mu.Unlock()
	k.log.App.Debug().Str("res", res.pretty()).Int("count", len(list.Items)).Msg("Resync complete")
	return nil
}

// wait pauses before a retry and reports whether the pause ran to its end,
// false meaning the context was cancelled meanwhile
func (k *KubernetesService) wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (k *KubernetesService) runWatcher(res watchedResource, w watch.Interface, resyncTicker *time.Ticker, ctx context.Context) bool {
	for {
		select {
		case <-ctx.Done():
			w.Stop()
			return false
		case event, ok := <-w.ResultChan():
			if !ok {
				k.log.App.Warn().Str("res", res.pretty()).Msg("Watcher channel closed, restarting watcher")
				w.Stop()
				return k.wait(ctx, 5*time.Second)
			}
			item, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				k.log.App.Warn().Str("res", res.pretty()).Msg("Received unexpected event object, skipping")
				continue
			}
			newTypedItem, err := new(typedItem).fromUnstructured(res.typ, item)
			if err != nil {
				k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Failed to decode resource, skipping")
				continue
			}
			switch event.Type {
			case watch.Added, watch.Modified, watch.Deleted:
				k.watchedItemChange(res, newTypedItem, event.Type)
			}
		case <-resyncTicker.C:
			if err := k.resyncGVR(res, ctx); err != nil {
				k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Periodic resync failed during watcher run")
			}
		}
	}
}

func (k *KubernetesService) watchGVR(res watchedResource, ctx context.Context) {
	resyncTicker := time.NewTicker(5 * time.Minute)
	defer resyncTicker.Stop()

	err := k.resyncGVR(res, ctx)

	k.firstListingDone(err)

	if err != nil {
		k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Initial resync failed, will retry")
		k.wait(ctx, 30*time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			k.log.App.Debug().Str("res", res.pretty()).Msg("Shutting down kubernetes watcher")
			return
		case <-resyncTicker.C:
			if err := k.resyncGVR(res, ctx); err != nil {
				k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Periodic resync failed, will retry")
			}
		default:
			watchCtx, cancel := context.WithCancel(ctx)
			watcher, err := k.client.Resource(res.gvr).Watch(watchCtx, metav1.ListOptions{})
			if err != nil {
				k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Failed to start watcher, will retry")
				cancel()
				k.wait(ctx, 10*time.Second)
				continue
			}
			k.log.App.Debug().Str("res", res.pretty()).Msg("Watcher started successfully")
			if !k.runWatcher(res, watcher, resyncTicker, watchCtx) {
				cancel()
				return
			}
			cancel()
		}
	}
}

// firstListingDone records how the first listing of a supported resource
// went. A resource that is not watched is recorded without being listed.
func (k *KubernetesService) firstListingDone(err error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if err != nil && k.syncErr == nil {
		k.syncErr = err
	}

	k.pending--

	if k.pending == 0 {
		close(k.synced)
	}
}

// WaitForSync waits until every watched resource has been listed once, which
// is when the labels of the cluster are known, and returns the error of a
// listing that failed
func (k *KubernetesService) WaitForSync(ctx context.Context) error {
	select {
	case <-k.synced:
	case <-ctx.Done():
		return context.Cause(ctx)
	}

	k.mu.RLock()
	defer k.mu.RUnlock()

	return k.syncErr
}

func (k *KubernetesService) Lookup(locator func(name string, app *model.App)) error {
	if !k.connected {
		k.log.App.Debug().Msg("Kubernetes label provider not started, skipping")
		return nil
	}

	k.runLocator(locator)

	return nil
}
