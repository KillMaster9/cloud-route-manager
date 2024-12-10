// SPDX-License-Identifier:Apache-2.0

package k8s

import (
	"cloud-route-manager/pkg/config"
	"cloud-route-manager/pkg/router"
	"context"
	"errors"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/yaml"
	"os"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
)

// Client watches a Kubernetes cluster and translates events into
// Controller method calls.
type Client struct {
	logger log.Logger

	client *kubernetes.Clientset
	events record.EventRecorder
	queue  workqueue.RateLimitingInterface

	cmIndexer     cache.Indexer
	cmInformer    cache.Controller
	syncFuncs     []cache.InformerSynced
	configChanged func(log.Logger, *config.Config) SyncState
	synced        func(log.Logger)
	OldResource   *v1.ConfigMap
}

// SyncState is the result of calling synchronization callbacks.
type SyncState int

const (
	// The update was processed successfully.
	SyncStateSuccess SyncState = iota
	// The update caused a transient error, the k8s client should
	// retry later.
	SyncStateError
	// The update was accepted, but requires reprocessing all watched
	// services.
	SyncStateReprocessAll
	// The update caused a non transient error, the k8s client should
	// just report and giveup.
	SyncStateErrorNoRetry
)

// Config specifies the configuration of the Kubernetes
// client/watcher.
type Config struct {
	ProcessName   string
	ConfigMapName string
	ConfigMapNS   string
	NodeName      string
	Logger        log.Logger
	Kubeconfig    string
	ConfigChanged func(log.Logger, *config.Config) SyncState
	Synced        func(log.Logger)
}

type cmKey string
type synced string

// New connects to masterAddr, using kubeconfig to authenticate.
//
// The client uses processName to identify itself to the cluster
// (e.g. when logging events).
//
//nolint:godot
func New(cfg *Config) (*Client, error) {
	var (
		k8sConfig *rest.Config
		err       error
	)

	if cfg.Kubeconfig == "" {
		// if the user didn't provide a config file, assume that we're
		// running inside k8s.
		k8sConfig, err = rest.InClusterConfig()
	} else {
		// the user provided a config file, so use that.  InClusterConfig
		// would also work in this case but it emits an annoying warning.
		k8sConfig, err = clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
	}
	if err != nil {
		return nil, fmt.Errorf("building client config: %s", err)
	}
	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, fmt.Errorf("creating Kubernetes client: %s", err)
	}

	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: v1core.New(clientset.CoreV1().RESTClient()).Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: cfg.ProcessName})

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	c := &Client{
		logger:      cfg.Logger,
		client:      clientset,
		events:      recorder,
		queue:       queue,
		OldResource: nil,
	}

	if cfg.ConfigChanged != nil {
		cmHandlers := cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				if err == nil {
					c.queue.Add(cmKey(key))
				}
			},
			UpdateFunc: func(old interface{}, new interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(new)
				if err == nil {
					c.queue.Add(cmKey(key))
				}
				c.OldResource = old.(*v1.ConfigMap).DeepCopy()
			},
			DeleteFunc: func(obj interface{}) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err == nil {
					c.queue.Add(cmKey(key))
				}
			},
		}
		cmWatcher := cache.NewListWatchFromClient(c.client.CoreV1().RESTClient(), "configmaps", cfg.ConfigMapNS, fields.OneTermEqualSelector("metadata.name", cfg.ConfigMapName))
		c.cmIndexer, c.cmInformer = cache.NewIndexerInformer(cmWatcher, &v1.ConfigMap{}, 0, cmHandlers, cache.Indexers{})

		c.configChanged = cfg.ConfigChanged
		c.syncFuncs = append(c.syncFuncs, c.cmInformer.HasSynced)
	}

	if cfg.Synced != nil {
		c.synced = cfg.Synced
	}

	return c, nil
}

// Run watches for events on the Kubernetes cluster, and dispatches
// calls to the Controller.
func (c *Client) Run(stopCh <-chan struct{}) error {

	if c.cmInformer != nil {
		go c.cmInformer.Run(stopCh)
	}

	if !cache.WaitForCacheSync(stopCh, c.syncFuncs...) {
		return errors.New("timed out waiting for cache sync")
	}

	c.queue.Add(synced(""))

	if stopCh != nil {
		go func() {
			<-stopCh
			c.queue.ShutDown()
		}()
	}

	for {
		key, quit := c.queue.Get()
		if quit {
			return nil
		}
		st := c.sync(key)
		switch st {
		case SyncStateErrorNoRetry, SyncStateSuccess:
			c.queue.Forget(key)
		case SyncStateError:
			c.queue.AddRateLimited(key)
		case SyncStateReprocessAll:
			c.queue.Forget(key)
			c.ForceSync()
		}
	}
}

// ForceSync reprocess all watched services.
func (c *Client) ForceSync() {
	//todo ...
}

// Infof logs an informational event about svc to the Kubernetes cluster.
func (c *Client) Infof(svc *v1.Service, kind, msg string, args ...interface{}) {
	c.events.Eventf(svc, v1.EventTypeNormal, kind, msg, args...)
}

// Errorf logs an error event about svc to the Kubernetes cluster.
func (c *Client) Errorf(svc *v1.Service, kind, msg string, args ...interface{}) {
	c.events.Eventf(svc, v1.EventTypeWarning, kind, msg, args...)
}

func (c *Client) sync(key interface{}) SyncState {
	defer c.queue.Done(key)

	switch k := key.(type) {

	case cmKey:
		l := log.With(c.logger, "configmap", string(k))
		cmi, exists, err := c.cmIndexer.GetByKey(string(k))
		if err != nil {
			level.Error(l).Log("op", "getConfigMap", "error", err, "msg", "failed to get configmap")
			return SyncStateError
		}
		if !exists {
			return c.configChanged(l, nil)
		}

		// Note that configs that we can read, but that fail parsing
		// or validation, result in a "synced" state, because the
		// config is not going to parse any better until the k8s
		// object changes to fix the issue.
		cm := cmi.(*v1.ConfigMap)
		cfg := &config.Config{}
		err = yaml.Unmarshal([]byte(config.FormatData(cm.Data)), cfg)
		if err != nil {
			level.Error(l).Log("event", "configStale", "error", err, "msg", "config (re)load failed, config marked stale")
			return SyncStateError
		}

		st := c.configChanged(l, cfg)
		if st == SyncStateErrorNoRetry || st == SyncStateError {
			level.Error(l).Log("event", "configStale", "error", err, "msg", "config (re)load failed, config marked stale")
			return st
		}

		level.Info(l).Log("event", "configLoaded", "msg", "config (re)loaded")
		return st

	case synced:
		if c.synced != nil {
			c.synced(c.logger)
		}
		return SyncStateSuccess

	default:
		panic(fmt.Errorf("unknown key type for %#v (%T)", key, key))
	}
}

func (c *Client) UpdateSystemPodRoute(newSubnetMap, oldSubnetMap map[string]string, cmpVipChanged bool) error {
	l := log.With(c.logger, "configmap")
	//Get nodeName
	nodeName := os.Getenv("NODE_NAME")
	if len(nodeName) == 0 {
		level.Error(l).Log("event", "configStale", "error", "NODE_NAME is empty", "msg", "config (re)load failed, config marked stale")
		return fmt.Errorf("Node name not found")
	}

	//Delete Pod for label list {app:icks-agent,app:oap,app:jaeger,app:kube-eventer}
	type podLabel map[string]string
	type KeyValue struct {
		Key   string
		Value podLabel
	}
	oapLabelSelector := map[string]string{"app": "oap"}
	kubeEventerLabelSelector := map[string]string{"app": "kube-eventer"}
	jaegerLabelSelector := map[string]string{"app": "jaeger"}
	icksAgentLabelSelector := map[string]string{"app": "icks-agent"}
	ivethControllerLabelSelector := map[string]string{"app.kubernetes.io/component": "controller-arm64-amd64-arm64-amd64-amd64-arm64-arm64-amd64"}
	systemPod := []KeyValue{
		{"istio-system", oapLabelSelector},
		{"kube-system", kubeEventerLabelSelector},
		{"istio-system", jaegerLabelSelector},
		{"kube-system", icksAgentLabelSelector},
		{"kube-system", ivethControllerLabelSelector}}

	if cmpVipChanged {
		for _, pod := range systemPod {
			err := c.RestartSystemPod(l, pod.Key, nodeName, pod.Value)
			if err != nil {
				return err
			}
		}
	}

	if router.CheckVeleroNetworkChanged(newSubnetMap, oldSubnetMap) {
		fmt.Println("velero Pod external network has changed, restart velero pod.")
		err := c.RestartSystemPod(l, "velero", nodeName, nil)
		if err != nil {
			return err
		}
	}

	return nil

}

func (c *Client) RestartSystemPod(l log.Logger, namespace string, nodeName string, label map[string]string) error {
	ListOptions := metav1.ListOptions{}
	if label != nil {
		ListOptions = metav1.ListOptions{LabelSelector: labels.FormatLabels(label)}
	}

	Pods, err := c.client.CoreV1().Pods(namespace).List(context.TODO(), ListOptions)
	if err != nil {
		level.Error(l).Log("event", "getPods", "error", err, "msg", "get  pods failed by labelSelector:", label)
		return err
	}
	for _, pod := range Pods.Items {
		if pod.Spec.NodeName == nodeName {
			err = c.client.CoreV1().Pods(namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
			if err != nil {
				level.Error(l).Log("event", "deletePod", "error", err, "msg", "Restart  pod error")
				return err
			}
		}
	}
	return nil
}
