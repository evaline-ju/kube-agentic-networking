/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"k8s.io/utils/ptr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1informers "k8s.io/client-go/informers/core/v1"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1"
	gatewayinformersv1beta1 "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1beta1"
	gatewayinformersxv1alpha1 "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apisx/v1alpha1"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"
	gatewaylistersv1beta1 "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1beta1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha1 "sigs.k8s.io/gateway-api/apisx/v1alpha1"
	gatewaylistersxv1alpha1 "sigs.k8s.io/gateway-api/pkg/client/listers/apisx/v1alpha1"

	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions/api/v0alpha0"
	agenticinformersv1alpha1 "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions/api/v1alpha1"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
	agenticlistersv1alpha1 "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v1alpha1"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/envoy"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/xds"
	"sigs.k8s.io/kube-agentic-networking/pkg/translator"
)

// maxGatewaySyncRetries is the maximum number of rate-limited requeues for a
// single Gateway key before the worker drops it (avoids infinite hot loops).
const maxGatewaySyncRetries = 30

// maxBackendFinalizerRetries is the same cap for the XBackend finalizer queue.
const maxBackendFinalizerRetries = 15

type coreResources struct {
	client kubernetes.Interface

	nsLister corev1listers.NamespaceLister
	nsSynced cache.InformerSynced

	svcLister corev1listers.ServiceLister
	svcSynced cache.InformerSynced

	endpointSliceLister discoverylisters.EndpointSliceLister
	endpointSliceSynced cache.InformerSynced

	secretLister corev1listers.SecretLister
	secretSynced cache.InformerSynced

	configMapLister corev1listers.ConfigMapLister
	configMapSynced cache.InformerSynced
}

type gatewayResources struct {
	client gatewayclient.Interface

	gatewayClassLister gatewaylisters.GatewayClassLister
	gatewayClassSynced cache.InformerSynced

	gatewayLister  gatewaylisters.GatewayLister
	gatewayIndexer cache.Indexer
	gatewaySynced  cache.InformerSynced

	httprouteLister      gatewaylisters.HTTPRouteLister
	httprouteIndexer     cache.Indexer
	referenceGrantLister gatewaylistersv1beta1.ReferenceGrantLister
	httprouteSynced      cache.InformerSynced
	referenceGrantSynced cache.InformerSynced

	xTelemetryPolicyLister gatewaylistersxv1alpha1.XTelemetryPolicyLister
	xTelemetryPolicySynced cache.InformerSynced
}

type agenticNetResources struct {
	client agenticclient.Interface

	backendLister agenticlisters.XBackendLister
	backendSynced cache.InformerSynced

	accessPolicyLister  agenticlistersv1alpha1.XAccessPolicyLister
	accessPolicyIndexer cache.Indexer
	accessPolicySynced  cache.InformerSynced
}

// Controller is the controller implementation for Gateway resources
type Controller struct {
	core    coreResources
	gateway gatewayResources
	agentic agenticNetResources

	agenticIdentityTrustDomain string
	envoyImage                 string

	gatewayqueue          workqueue.TypedRateLimitingInterface[string]
	backendFinalizerQueue workqueue.TypedRateLimitingInterface[string]
	xdsServer             *xds.Server
	translator            *translator.Translator
}

// New returns a new *Controller with the event handlers setup for types we are interested in.
func New(
	ctx context.Context,
	agenticIdentityTrustDomain string,
	envoyImage string,
	tracingSampleRate float64,
	kubeClientSet kubernetes.Interface,
	gwClientSet gatewayclient.Interface,
	agenticClientSet agenticclient.Interface,
	namespaceInformer corev1informers.NamespaceInformer,
	serviceInformer corev1informers.ServiceInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer,
	secretInformer corev1informers.SecretInformer,
	configMapInformer corev1informers.ConfigMapInformer,
	gatewayClassInformer gatewayinformers.GatewayClassInformer,
	gatewayInformer gatewayinformers.GatewayInformer,
	httprouteInformer gatewayinformers.HTTPRouteInformer,
	referenceGrantInformer gatewayinformersv1beta1.ReferenceGrantInformer,
	backendInformer agenticinformers.XBackendInformer,
	accessPolicyInformer agenticinformersv1alpha1.XAccessPolicyInformer,
	telemetryPolicyInformer gatewayinformersxv1alpha1.XTelemetryPolicyInformer,
) (*Controller, error) {
	apInformer := accessPolicyInformer.Informer()
	if err := apInformer.AddIndexers(cache.Indexers{AccessPolicyTargetRefIndex: accessPolicyTargetRefIndexFunc}); err != nil {
		return nil, fmt.Errorf("add AccessPolicy targetRef index: %w", err)
	}

	if err := httprouteInformer.Informer().AddIndexers(cache.Indexers{HTTPRouteBackendRefNamespaceIndex: HTTPRouteBackendRefNamespaceIndexFunc}); err != nil {
		return nil, fmt.Errorf("add HTTPRoute backend reference namespace index: %w", err)
	}

	if err := gatewayInformer.Informer().AddIndexers(cache.Indexers{GatewaySecretRefNamespaceIndex: GatewaySecretRefNamespaceIndexFunc}); err != nil {
		return nil, fmt.Errorf("add Gateway secret reference namespace index: %w", err)
	}

	c := &Controller{
		core: coreResources{
			client:              kubeClientSet,
			nsLister:            namespaceInformer.Lister(),
			nsSynced:            namespaceInformer.Informer().HasSynced,
			svcLister:           serviceInformer.Lister(),
			svcSynced:           serviceInformer.Informer().HasSynced,
			endpointSliceLister: endpointSliceInformer.Lister(),
			endpointSliceSynced: endpointSliceInformer.Informer().HasSynced,
			secretLister:        secretInformer.Lister(),
			secretSynced:        secretInformer.Informer().HasSynced,
			configMapLister:     configMapInformer.Lister(),
			configMapSynced:     configMapInformer.Informer().HasSynced,
		},
		gateway: gatewayResources{
			client:               gwClientSet,
			gatewayClassLister:   gatewayClassInformer.Lister(),
			gatewayClassSynced:   gatewayClassInformer.Informer().HasSynced,
			gatewayLister:        gatewayInformer.Lister(),
			gatewayIndexer:       gatewayInformer.Informer().GetIndexer(),
			gatewaySynced:        gatewayInformer.Informer().HasSynced,
			httprouteLister:      httprouteInformer.Lister(),
			httprouteIndexer:     httprouteInformer.Informer().GetIndexer(),
			referenceGrantLister: referenceGrantInformer.Lister(),
			httprouteSynced:      httprouteInformer.Informer().HasSynced,
			referenceGrantSynced: referenceGrantInformer.Informer().HasSynced,

			xTelemetryPolicyLister: telemetryPolicyInformer.Lister(),
			xTelemetryPolicySynced: telemetryPolicyInformer.Informer().HasSynced,
		},
		agentic: agenticNetResources{
			client:              agenticClientSet,
			backendLister:       backendInformer.Lister(),
			backendSynced:       backendInformer.Informer().HasSynced,
			accessPolicyLister:  accessPolicyInformer.Lister(),
			accessPolicyIndexer: apInformer.GetIndexer(),
			accessPolicySynced:  apInformer.HasSynced,
		},
		agenticIdentityTrustDomain: agenticIdentityTrustDomain,
		envoyImage:                 envoyImage,
		gatewayqueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "gateway"},
		),
		backendFinalizerQueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "backend-finalizer"},
		),
		xdsServer: xds.NewServer(ctx),
	}

	c.translator = translator.New(
		agenticIdentityTrustDomain,
		kubeClientSet,
		gwClientSet,
		namespaceInformer.Lister(),
		serviceInformer.Lister(),
		endpointSliceInformer.Lister(),
		secretInformer.Lister(),
		configMapInformer.Lister(),
		gatewayInformer.Lister(),
		httprouteInformer.Lister(),
		referenceGrantInformer.Lister(),
		accessPolicyInformer.Lister(),
		backendInformer.Lister(),
		telemetryPolicyInformer.Lister(),
		tracingSampleRate,
	)

	// Setup event handlers for all relevant resources.
	if err := c.setupGatewayClassEventHandlers(ctx, gatewayClassInformer); err != nil {
		return nil, err
	}
	if err := c.setupGatewayEventHandlers(gatewayInformer); err != nil {
		return nil, err
	}
	if err := c.setupHTTPRouteEventHandlers(httprouteInformer); err != nil {
		return nil, err
	}
	if err := c.setupReferenceGrantEventHandlers(referenceGrantInformer); err != nil {
		return nil, err
	}
	if err := c.setupBackendEventHandlers(backendInformer); err != nil {
		return nil, err
	}
	if err := c.setupAccessPolicyEventHandlers(accessPolicyInformer); err != nil {
		return nil, err
	}
	if err := c.setupTelemetryPolicyEventHandlers(telemetryPolicyInformer); err != nil {
		return nil, err
	}
	if err := c.setupServiceEventHandlers(serviceInformer); err != nil {
		return nil, err
	}
	if err := c.setupEndpointSliceEventHandlers(endpointSliceInformer); err != nil {
		return nil, err
	}

	return c, nil
}

// Run will
// - sync informer caches and start workers.
// - start the xDS server
func (c *Controller) Run(ctx context.Context, workers int) error {
	defer runtime.HandleCrashWithContext(ctx)
	defer c.gatewayqueue.ShutDown()
	defer c.backendFinalizerQueue.ShutDown()

	// start the xDS server
	klog.Info("Starting the Envoy xDS server")
	if err := c.xdsServer.Run(ctx); err != nil {
		return fmt.Errorf("failed to start xDS server: %w", err)
	}

	klog.Info("Waiting for informer caches to sync")
	// endpointSliceSynced is intentionally excluded: without discovery.k8s.io/endpointslices
	// RBAC the reflector never becomes synced and would block all workers. Service backends
	// fall back to STRICT_DNS when the EndpointSlice lister is empty (see translator).
	if ok := cache.WaitForCacheSync(ctx.Done(),
		c.core.nsSynced,
		c.core.svcSynced,
		c.core.secretSynced,
		c.core.configMapSynced,
		c.gateway.gatewayClassSynced,
		c.gateway.gatewaySynced,
		c.gateway.httprouteSynced,
		c.gateway.referenceGrantSynced,
		c.gateway.xTelemetryPolicySynced,
		c.agentic.backendSynced,
		c.agentic.accessPolicySynced); !ok {
		return errors.New("failed to wait for caches to sync")
	}

	klog.InfoS("Starting gateway workers", "count", workers)
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}
	klog.InfoS("Starting backend finalizer workers", "count", workers)
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runBackendFinalizerWorker, time.Second)
	}

	klog.Info("Started workers")
	<-ctx.Done()
	klog.Info("Shutting down workers")

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextGatewayItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextGatewayItem(ctx) {
	}
}

// processNextGatewayItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processNextGatewayItem(ctx context.Context) bool {
	obj, shutdown := c.gatewayqueue.Get()
	if shutdown {
		return false
	}
	defer c.gatewayqueue.Done(obj)

	// We expect strings (namespace/name) to come off the workqueue.
	if err := c.syncGateway(ctx, obj); err != nil {
		if c.gatewayqueue.NumRequeues(obj) < maxGatewaySyncRetries {
			c.gatewayqueue.AddRateLimited(obj)
			klog.ErrorS(err, "Error syncing gateway; will retry with rate limit", "key", obj, "requeues", c.gatewayqueue.NumRequeues(obj))
		} else {
			c.gatewayqueue.Forget(obj)
			klog.ErrorS(err, "Dropping gateway sync after max retries", "key", obj, "maxRetries", maxGatewaySyncRetries)
		}
		return true
	}

	// Finally, if no error occurs we Forget this item so it does not
	// get queued again until another change happens.
	c.gatewayqueue.Forget(obj)
	klog.InfoS("Successfully synced", "key", obj)
	return true
}

func (c *Controller) runBackendFinalizerWorker(ctx context.Context) {
	for c.processNextBackendFinalizerItem(ctx) {
	}
}

func (c *Controller) processNextBackendFinalizerItem(ctx context.Context) bool {
	obj, shutdown := c.backendFinalizerQueue.Get()
	if shutdown {
		return false
	}
	defer c.backendFinalizerQueue.Done(obj)
	if err := c.syncBackendFinalizer(ctx, obj); err != nil {
		if c.backendFinalizerQueue.NumRequeues(obj) < maxBackendFinalizerRetries {
			c.backendFinalizerQueue.AddRateLimited(obj)
			klog.ErrorS(err, "Error syncing backend finalizer; will retry with rate limit", "key", obj, "requeues", c.backendFinalizerQueue.NumRequeues(obj))
		} else {
			c.backendFinalizerQueue.Forget(obj)
			klog.ErrorS(err, "Dropping backend finalizer sync after max retries", "key", obj, "maxRetries", maxBackendFinalizerRetries)
		}
		return true
	}
	c.backendFinalizerQueue.Forget(obj)
	return true
}

// syncGateway compares the actual state with the desired, and attempts to
// converge the two.
func (c *Controller) syncGateway(ctx context.Context, key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(2).Infof("Finished syncing gateway %q (%v)", key, time.Since(startTime))
	}()

	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s (err: %w)", key, err))
		return nil
	}

	logger := klog.FromContext(ctx).WithValues("gateway", klog.KRef(namespace, name))
	ctx = klog.NewContext(ctx, logger)

	// Get the Gateway resource with this namespace/name
	gateway, err := c.gateway.gatewayLister.Gateways(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		logger.Info("Gateway deleted, cleaning up associated resources.")
		return envoy.DeleteProxy(ctx, c.core.client, namespace, name)
	}
	if err != nil {
		return fmt.Errorf("failed to get gateway %s: %w", key, err)
	}

	// Only reconcile Gateways whose spec.gatewayClassName refers to a GatewayClass
	if !c.isGatewayOwnedByController(gateway) {
		logger.V(4).Info("Skipping Gateway: not owned by this controller (GatewayClass controllerName mismatch or GatewayClass not found)",
			"gateway", klog.KRef(gateway.Namespace, gateway.Name),
			"gatewayClassName", string(gateway.Spec.GatewayClassName))
		return nil
	}

	// If Gateway is being deleted, block until no HTTPRoutes or AccessPolicies reference it, then clean up and remove finalizer.
	if gateway.DeletionTimestamp != nil {
		if hasHTTPRoutesReferencingGateway(c, gateway) {
			logger.V(4).Info("Gateway has HTTPRoutes still referencing it, blocking deletion")
			return nil
		}
		if hasAccessPoliciesTargetingGateway(c, gateway) {
			logger.V(4).Info("Gateway has AccessPolicies still targeting it, blocking deletion")
			return nil
		}
		if hasTelemetryPoliciesTargetingGateway(c, gateway) {
			logger.V(4).Info("Gateway has XTelemetryPolicies still targeting it, blocking deletion")
			return nil
		}
		if errDel := envoy.DeleteProxy(ctx, c.core.client, namespace, name); errDel != nil {
			return errDel
		}
		if err = c.updateGatewayRemoveFinalizer(ctx, namespace, name); err != nil {
			return fmt.Errorf("failed to remove finalizer from Gateway: %w", err)
		}
		return nil
	}

	finalizerAdded, err := c.ensureGatewayFinalizer(ctx, namespace, name)
	if err != nil {
		return fmt.Errorf("failed to add finalizer to Gateway: %w", err)
	}
	if finalizerAdded {
		c.gatewayqueue.Add(key)
		return nil
	}

	logger.Info("Syncing gateway")

	newGW := gateway.DeepCopy()

	// Ensure Envoy proxy deployment and service exist. The bootstrap telemetry
	// options (tracer enabled, service name, collector destination) come from the
	// XTelemetryPolicy targeting this Gateway, if any.
	telemetryBootstrap := c.translator.ResolveTelemetryBootstrap(gateway)
	rm := envoy.NewResourceManager(c.core.client, gateway, c.envoyImage, c.agenticIdentityTrustDomain,
		envoy.TelemetryOptions{
			TracingEnabled:   telemetryBootstrap.TracingEnabled,
			ServiceName:      telemetryBootstrap.ServiceName,
			CollectorAddress: telemetryBootstrap.CollectorAddress,
			CollectorPort:    telemetryBootstrap.CollectorPort,
		})
	proxyAddress, ensureProxyErr := rm.EnsureProxyExist(ctx)
	if ensureProxyErr != nil {
		if c.translator != nil {
			if _, _, httpRouteStatuses, _, translateErr := c.translator.TranslateGatewayToXDS(ctx, gateway); translateErr == nil {
				_ = c.updateHTTPRouteStatuses(ctx, httpRouteStatuses)
			}
		}
		updateErr := updateGatewayStatus(ctx, c, gateway, newGW, nil, ensureProxyErr)
		return errors.Join(ensureProxyErr, updateErr)
	}

	// TODO: Add support for IPv6?
	newGW.Status.Addresses = []gatewayv1.GatewayStatusAddress{}
	if net.ParseIP(proxyAddress) != nil {
		// proxyAddress is an IP address
		newGW.Status.Addresses = append(newGW.Status.Addresses,
			gatewayv1.GatewayStatusAddress{
				Type:  ptr.To(gatewayv1.IPAddressType),
				Value: proxyAddress,
			})
	} else {
		// proxyAddress is a hostname
		newGW.Status.Addresses = append(newGW.Status.Addresses,
			gatewayv1.GatewayStatusAddress{
				Type:  ptr.To(gatewayv1.HostnameAddressType),
				Value: proxyAddress,
			})
	}

	logger.Info("Ensured Envoy proxy for gateway exists", "nodeID", rm.NodeID(), "proxyAddress", proxyAddress)

	// Translate Gateway to xDS resources (includes only current HTTPRoutes/XAccessPolicies; stale rules are omitted).
	resources, listenerStatuses, httpRouteStatuses, _, err := c.translator.TranslateGatewayToXDS(ctx, gateway)
	if err != nil {
		updateErr := updateGatewayStatus(ctx, c, gateway, newGW, nil, fmt.Errorf("failed to translate gateway to xDS resources: %w", err))
		return errors.Join(err, updateErr)
	}

	logger.Info("Translated gateway to xDS resources")

	newGW.Status.Listeners = listenerStatuses
	// Update the xDS server with the new resources.
	xdsErr := c.xdsServer.UpdateXDSServer(ctx, rm.NodeID(), resources)
	updateGatewayStatusErr := updateGatewayStatus(ctx, c, gateway, newGW, listenerStatuses, xdsErr)
	updateHTTPRouteStatusErr := c.updateHTTPRouteStatuses(ctx, httpRouteStatuses)
	return errors.Join(xdsErr, updateGatewayStatusErr, updateHTTPRouteStatusErr)
}

func (c *Controller) updateGatewayRemoveFinalizer(ctx context.Context, namespace, name string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest, err := c.gateway.gatewayLister.Gateways(namespace).Get(name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		u := latest.DeepCopy()
		if !removeFinalizer(&u.ObjectMeta, constants.GatewayFinalizer) {
			return nil
		}
		_, err = c.gateway.client.GatewayV1().Gateways(namespace).Update(ctx, u, metav1.UpdateOptions{})
		return err
	})
}

// updateGatewayStatus updates the Gateway status in the API server if it has changed.
// Note: this function modifies newGW.
func updateGatewayStatus(ctx context.Context, c *Controller, gateway *gatewayv1.Gateway, newGW *gatewayv1.Gateway, listenerStatuses []gatewayv1.ListenerStatus, syncErr error) error {
	setGatewayConditions(newGW, listenerStatuses, syncErr)

	if reflect.DeepEqual(gateway.Status, newGW.Status) {
		return nil
	}

	if _, statusErr := c.gateway.client.GatewayV1().Gateways(newGW.Namespace).UpdateStatus(ctx, newGW, metav1.UpdateOptions{}); statusErr != nil {
		klog.FromContext(ctx).Error(statusErr, "failed to update gateway status")
		return fmt.Errorf("failed to update gateway status: %w", statusErr)
	}
	klog.FromContext(ctx).Info("Updated gateway status")
	return nil
}

// ensureGatewayFinalizer adds the controller finalizer via the API when missing.
// It returns (true, nil) when the finalizer was absent at the start of the call and is present
// after a successful retry loop (caller should requeue and exit early so metadata is fresh).
func (c *Controller) ensureGatewayFinalizer(ctx context.Context, namespace, name string) (requeue bool, err error) {
	gw, err := c.gateway.gatewayLister.Gateways(namespace).Get(name)
	if err != nil {
		return false, err
	}
	hadFinalizer := sets.New(gw.Finalizers...).Has(constants.GatewayFinalizer)
	probe := gw.DeepCopy()
	if !ensureFinalizer(&probe.ObjectMeta, constants.GatewayFinalizer) {
		return false, nil
	}
	if retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest, getErr := c.gateway.gatewayLister.Gateways(namespace).Get(name)
		if getErr != nil {
			return getErr
		}
		u := latest.DeepCopy()
		if !ensureFinalizer(&u.ObjectMeta, constants.GatewayFinalizer) {
			return nil
		}
		_, updErr := c.gateway.client.GatewayV1().Gateways(namespace).Update(ctx, u, metav1.UpdateOptions{})
		return updErr
	}); retryErr != nil {
		return false, retryErr
	}
	fresh, err := c.gateway.gatewayLister.Gateways(namespace).Get(name)
	if err != nil {
		return false, err
	}
	nowHas := sets.New(fresh.Finalizers...).Has(constants.GatewayFinalizer)
	return !hadFinalizer && nowHas, nil
}

// hasHTTPRoutesReferencingGateway returns true if any HTTPRoute has a ParentRef to the given Gateway.
func hasHTTPRoutesReferencingGateway(c *Controller, gw *gatewayv1.Gateway) bool {
	routes, err := c.gateway.httprouteLister.List(labels.Everything())
	if err != nil {
		klog.V(4).ErrorS(err, "failed to list HTTPRoutes for Gateway finalizer")
		return true // conservatively block
	}
	for _, route := range routes {
		for _, parentRef := range route.Spec.ParentRefs {
			if (parentRef.Group != nil && string(*parentRef.Group) != gatewayv1.GroupName) ||
				(parentRef.Kind != nil && string(*parentRef.Kind) != "Gateway") {
				continue
			}
			refNamespace := route.Namespace
			if parentRef.Namespace != nil {
				refNamespace = string(*parentRef.Namespace)
			}
			if string(parentRef.Name) == gw.Name && refNamespace == gw.Namespace {
				return true
			}
		}
	}
	return false
}

// hasAccessPoliciesTargetingGateway returns true if any XAccessPolicy has a targetRef to the given Gateway.
// Used to block Gateway finalizer removal until all targeting AccessPolicies are removed (avoids dangling refs).
func hasAccessPoliciesTargetingGateway(c *Controller, gw *gatewayv1.Gateway) bool {
	policies, err := c.agentic.accessPolicyLister.XAccessPolicies(gw.Namespace).List(labels.Everything())
	if err != nil {
		klog.V(4).ErrorS(err, "failed to list AccessPolicies for Gateway finalizer")
		return true // conservatively block
	}
	for _, policy := range policies {
		for _, targetRef := range policy.Spec.TargetRefs {
			if !isGatewayTargetRef(targetRef) {
				continue
			}
			if string(targetRef.Name) == gw.Name {
				return true
			}
		}
	}
	return false
}

// TelemetryPolicyTargetRefIndex is the index name for looking up XTelemetryPolicies
// by target ref (namespace/name of Gateway).
const TelemetryPolicyTargetRefIndex = "telemetryPolicyTargetRef"

// telemetryPolicyTargetRefIndexFunc indexes XTelemetryPolicies by each Gateway
// targetRef (namespace/name), so Service and Gateway events can find affected
// policies without listing everything.
func telemetryPolicyTargetRefIndexFunc(obj interface{}) ([]string, error) {
	policy, ok := obj.(*gatewayapiv1alpha1.XTelemetryPolicy)
	if !ok {
		return nil, nil
	}
	var keys []string
	for _, targetRef := range policy.Spec.TargetRefs {
		if !isTelemetryGatewayTargetRef(targetRef) {
			continue
		}
		keys = append(keys, policy.Namespace+"/"+string(targetRef.Name))
	}
	return keys, nil
}

func isTelemetryGatewayTargetRef(targetRef gatewayv1.LocalObjectReference) bool {
	return targetRef.Group == gatewayv1.Group(gatewayv1.GroupName) && targetRef.Kind == gatewayv1.Kind("Gateway")
}

func (c *Controller) setupTelemetryPolicyEventHandlers(telemetryPolicyInformer gatewayinformersxv1alpha1.XTelemetryPolicyInformer) error {
	if err := telemetryPolicyInformer.Informer().AddIndexers(cache.Indexers{
		TelemetryPolicyTargetRefIndex: telemetryPolicyTargetRefIndexFunc,
	}); err != nil {
		return fmt.Errorf("add XTelemetryPolicy targetRef index: %w", err)
	}
	_, err := telemetryPolicyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onTelemetryPolicyAdd,
		UpdateFunc: c.onTelemetryPolicyUpdate,
		DeleteFunc: c.onTelemetryPolicyDelete,
	})
	return err
}

func (c *Controller) onTelemetryPolicyAdd(obj interface{}) {
	policy := obj.(*gatewayapiv1alpha1.XTelemetryPolicy)
	klog.V(4).InfoS("Adding XTelemetryPolicy", "xtelemetrypolicy", klog.KObj(policy))
	c.reconcileTelemetryPolicies(context.Background(), policy.Namespace)
}

func (c *Controller) onTelemetryPolicyUpdate(old, newObj interface{}) {
	oldPolicy := old.(*gatewayapiv1alpha1.XTelemetryPolicy)
	newPolicy := newObj.(*gatewayapiv1alpha1.XTelemetryPolicy)
	if newPolicy.Generation != oldPolicy.Generation || newPolicy.DeletionTimestamp != oldPolicy.DeletionTimestamp {
		klog.V(4).InfoS("Updating XTelemetryPolicy", "xtelemetrypolicy", klog.KObj(newPolicy))
		c.reconcileTelemetryPolicies(context.Background(), newPolicy.Namespace)
	}
}

func (c *Controller) onTelemetryPolicyDelete(obj interface{}) {
	policy, ok := obj.(*gatewayapiv1alpha1.XTelemetryPolicy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "couldn't get object from tombstone", "obj", obj)
			return
		}
		policy, ok = tombstone.Obj.(*gatewayapiv1alpha1.XTelemetryPolicy)
		if !ok {
			klog.ErrorS(nil, "tombstone contained object that is not an XTelemetryPolicy", "obj", obj)
			return
		}
	}
	klog.V(4).InfoS("Deleting XTelemetryPolicy", "xtelemetrypolicy", klog.KObj(policy))
	// Deleting the winning policy may resolve a conflict for another policy, so
	// re-evaluate every telemetry policy in the namespace.
	c.reconcileTelemetryPolicies(context.Background(), policy.Namespace)
}

// reconcileTelemetryPolicies re-evaluates all XTelemetryPolicies in a namespace:
// it resolves conflicts (at most one policy per Gateway, oldest wins), validates
// targetRefs and provider backendRefs, updates policy statuses, and enqueues the
// Gateways targeted by any policy so their Envoy config is regenerated.
func (c *Controller) reconcileTelemetryPolicies(ctx context.Context, namespace string) {
	policies, err := c.gateway.xTelemetryPolicyLister.XTelemetryPolicies(namespace).List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "failed to list XTelemetryPolicies")
		return
	}

	// Track the winning policy per targeted Gateway (namespace/name).
	gatewayKeyToWinningPolicy := make(map[string]*gatewayapiv1alpha1.XTelemetryPolicy)
	for _, policy := range policies {
		if policy.DeletionTimestamp != nil {
			continue
		}
		for _, targetRef := range policy.Spec.TargetRefs {
			if !isTelemetryGatewayTargetRef(targetRef) {
				continue
			}
			key := policy.Namespace + "/" + string(targetRef.Name)
			if winner, ok := gatewayKeyToWinningPolicy[key]; !ok || isMoreSeniorTelemetryPolicy(policy, winner) {
				gatewayKeyToWinningPolicy[key] = policy
			}
		}
	}

	for _, policy := range policies {
		c.validateTelemetryPolicy(ctx, policy, gatewayKeyToWinningPolicy)
	}

	// Enqueue every Gateway targeted by any policy (winners pick up new config;
	// losers and deletes fall back to defaults).
	targeted := sets.New[string]()
	for _, policy := range policies {
		for _, targetRef := range policy.Spec.TargetRefs {
			if !isTelemetryGatewayTargetRef(targetRef) {
				continue
			}
			targeted.Insert(policy.Namespace + "/" + string(targetRef.Name))
		}
	}
	for key := range targeted {
		c.gatewayqueue.Add(key)
	}
}

// isMoreSeniorTelemetryPolicy returns true if p1 wins precedence over p2:
// older creation timestamp first, then lexicographically smaller name.
func isMoreSeniorTelemetryPolicy(p1, p2 *gatewayapiv1alpha1.XTelemetryPolicy) bool {
	if !p1.CreationTimestamp.Equal(&p2.CreationTimestamp) {
		return p1.CreationTimestamp.Before(&p2.CreationTimestamp)
	}
	return p1.Name < p2.Name
}

// validateTelemetryPolicy validates one XTelemetryPolicy and updates its status.
// It checks: valid Gateway targetRefs, supported attribute source types,
// conflict resolution against the winning policy map, and provider backendRef
// resolution (Service existence and cross-namespace ReferenceGrant permission).
func (c *Controller) validateTelemetryPolicy(ctx context.Context, policy *gatewayapiv1alpha1.XTelemetryPolicy, gatewayKeyToWinningPolicy map[string]*gatewayapiv1alpha1.XTelemetryPolicy) {
	type targetStatus struct {
		accepted bool
		reason   gatewayv1.PolicyConditionReason
		message  string
	}
	statuses := make(map[string]targetStatus, len(policy.Spec.TargetRefs))

	for _, targetRef := range policy.Spec.TargetRefs {
		key := policy.Namespace + "/" + string(targetRef.Name)
		accepted := true
		reason := gatewayv1.PolicyReasonAccepted
		message := "XTelemetryPolicy accepted for target"

		switch {
		case !isTelemetryGatewayTargetRef(targetRef):
			accepted = false
			reason = gatewayv1.PolicyReasonInvalid
			message = fmt.Sprintf("Unsupported targetRef group/kind %s/%s: only Gateway is supported", targetRef.Group, targetRef.Kind)
		default:
			if winner, ok := gatewayKeyToWinningPolicy[key]; ok && winner.Name != policy.Name {
				accepted = false
				reason = gatewayv1.PolicyReasonConflicted
				message = fmt.Sprintf("Another XTelemetryPolicy (%s) already targets Gateway %s; only one policy per Gateway is allowed", winner.Name, targetRef.Name)
			}
		}
		statuses[key] = targetStatus{accepted, reason, message}
	}

	// Validate tracing attributes: only Literal and Header source types are supported.
	for _, attr := range policy.Spec.Tracing.Attributes {
		if attr.SourceType == gatewayapiv1alpha1.AttributeSourceAttribute {
			for key := range statuses {
				s := statuses[key]
				s.accepted = false
				s.reason = gatewayv1.PolicyReasonInvalid
				s.message = fmt.Sprintf("Attribute %q uses sourceType Attribute, which is not yet supported by this implementation", attr.Name)
				statuses[key] = s
			}
		}
	}

	// Validate the provider backendRef when tracing is enabled: it must be a
	// Service that exists and is permitted by ReferenceGrant for cross-namespace refs.
	if policy.Spec.Tracing.Mode == gatewayapiv1alpha1.TracingModeEnabled {
		backendRef := policy.Spec.Tracing.Provider.BackendRef
		kind := gatewayv1.Kind("Service")
		if backendRef.Kind != nil {
			kind = *backendRef.Kind
		}
		group := gatewayv1.Group("")
		if backendRef.Group != nil {
			group = *backendRef.Group
		}

		resolvedRef := true
		switch {
		case group != gatewayv1.Group("") || kind != gatewayv1.Kind("Service"):
			for key := range statuses {
				c.updateTelemetryPolicyResolvedRefs(ctx, policy, key, false, "InvalidKind",
					fmt.Sprintf("Tracing provider backendRef must reference a Service, got %s/%s", group, kind))
			}
			resolvedRef = false
		default:
			backendNamespace := policy.Namespace
			if backendRef.Namespace != nil {
				backendNamespace = string(*backendRef.Namespace)
			}
			if _, err := c.core.svcLister.Services(backendNamespace).Get(string(backendRef.Name)); err != nil {
				if apierrors.IsNotFound(err) {
					for key := range statuses {
						c.updateTelemetryPolicyResolvedRefs(ctx, policy, key, false, "BackendNotFound",
							fmt.Sprintf("Tracing provider backendRef Service %s/%s not found", backendNamespace, backendRef.Name))
					}
				} else {
					klog.ErrorS(err, "failed to get Service for XTelemetryPolicy", "namespace", backendNamespace, "name", backendRef.Name, "policy", policy.Name)
				}
				resolvedRef = false
			} else if !allowedByReferenceGrantForTelemetry(backendNamespace, policy.Namespace, string(backendRef.Name), c) {
				for key := range statuses {
					c.updateTelemetryPolicyResolvedRefs(ctx, policy, key, false, "RefNotPermitted",
						fmt.Sprintf("Tracing provider backendRef Service %s/%s is not permitted by a ReferenceGrant", backendNamespace, backendRef.Name))
				}
				resolvedRef = false
			}
		}
		if !resolvedRef {
			// An unresolved backend also invalidates acceptance of the policy.
			for key, s := range statuses {
				if s.accepted {
					s.accepted = false
					s.reason = gatewayv1.PolicyReasonInvalid
					s.message = "Tracing provider backendRef could not be resolved"
					statuses[key] = s
				}
			}
		}
	}

	for key, s := range statuses {
		if err := c.updateTelemetryPolicyStatus(ctx, policy, key, s.accepted, s.reason, s.message); err != nil {
			klog.ErrorS(err, "failed to update XTelemetryPolicy status")
		}
	}
}

// allowedByReferenceGrantForTelemetry checks whether the policy's namespace is
// permitted to reference a Service in backendNamespace.
func allowedByReferenceGrantForTelemetry(backendNamespace, policyNamespace, serviceName string, c *Controller) bool {
	if backendNamespace == policyNamespace {
		return true
	}
	grants, err := c.gateway.referenceGrantLister.ReferenceGrants(backendNamespace).List(labels.Everything())
	if err != nil {
		klog.V(4).ErrorS(err, "failed to list ReferenceGrants", "namespace", backendNamespace)
		return false
	}
	for _, g := range grants {
		for _, from := range g.Spec.From {
			if string(from.Namespace) != policyNamespace || string(from.Group) != gatewayv1.GroupName || string(from.Kind) != "XTelemetryPolicy" {
				continue
			}
			for _, to := range g.Spec.To {
				if to.Group != gatewayv1.Group(corev1.GroupName) || to.Kind != gatewayv1.Kind("Service") {
					continue
				}
				if to.Name != nil && string(*to.Name) != serviceName {
					continue
				}
				return true
			}
		}
	}
	return false
}

// updateTelemetryPolicyStatus sets the Accepted condition for the given target
// (namespace/name of a Gateway) on the policy status.
func (c *Controller) updateTelemetryPolicyStatus(ctx context.Context, policy *gatewayapiv1alpha1.XTelemetryPolicy, gatewayKey string, accepted bool, reason gatewayv1.PolicyConditionReason, message string) error {
	_, gwName, _ := strings.Cut(gatewayKey, "/")
	parentRef := gatewayv1.ParentReference{
		Group:     ptr.To(gatewayv1.Group(gatewayv1.GroupName)),
		Kind:      ptr.To(gatewayv1.Kind("Gateway")),
		Namespace: ptr.To(gatewayv1.Namespace(policy.Namespace)),
		Name:      gatewayv1.ObjectName(gwName),
	}
	conditionStatus := metav1.ConditionFalse
	if accepted {
		conditionStatus = metav1.ConditionTrue
	}
	return c.updateTelemetryPolicyConditions(ctx, policy, parentRef, []metav1.Condition{{
		Type:               string(gatewayv1.PolicyConditionAccepted),
		Status:             conditionStatus,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: policy.Generation,
	}})
}

// updateTelemetryPolicyResolvedRefs sets the ResolvedRefs condition for the given
// target on the policy status.
func (c *Controller) updateTelemetryPolicyResolvedRefs(ctx context.Context, policy *gatewayapiv1alpha1.XTelemetryPolicy, gatewayKey string, resolved bool, reason, message string) error {
	_, gwName, _ := strings.Cut(gatewayKey, "/")
	parentRef := gatewayv1.ParentReference{
		Group:     ptr.To(gatewayv1.Group(gatewayv1.GroupName)),
		Kind:      ptr.To(gatewayv1.Kind("Gateway")),
		Namespace: ptr.To(gatewayv1.Namespace(policy.Namespace)),
		Name:      gatewayv1.ObjectName(gwName),
	}
	conditionStatus := metav1.ConditionFalse
	if resolved {
		conditionStatus = metav1.ConditionTrue
	}
	return c.updateTelemetryPolicyConditions(ctx, policy, parentRef, []metav1.Condition{{
		Type:               "ResolvedRefs",
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: policy.Generation,
	}})
}

// updateTelemetryPolicyConditions applies conditions to the policy status for the
// ancestor matching parentRef, creating the ancestor entry if needed.
func (c *Controller) updateTelemetryPolicyConditions(ctx context.Context, policy *gatewayapiv1alpha1.XTelemetryPolicy, parentRef gatewayv1.ParentReference, conditions []metav1.Condition) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh, err := c.gateway.xTelemetryPolicyLister.XTelemetryPolicies(policy.Namespace).Get(policy.Name)
		if err != nil {
			return err
		}
		policyCopy := fresh.DeepCopy()

		var ancestorStatus *gatewayv1.PolicyAncestorStatus
		for i := range policyCopy.Status.Ancestors {
			if reflect.DeepEqual(policyCopy.Status.Ancestors[i].AncestorRef, parentRef) {
				ancestorStatus = &policyCopy.Status.Ancestors[i]
				break
			}
		}
		if ancestorStatus == nil {
			if len(policyCopy.Status.Ancestors) >= 16 {
				return nil // status list is full; API max is 16 ancestors
			}
			policyCopy.Status.Ancestors = append(policyCopy.Status.Ancestors, gatewayv1.PolicyAncestorStatus{
				AncestorRef:    parentRef,
				ControllerName: gatewayv1.GatewayController(constants.ControllerName),
			})
			ancestorStatus = &policyCopy.Status.Ancestors[len(policyCopy.Status.Ancestors)-1]
		}
		for _, cond := range conditions {
			meta.SetStatusCondition(&ancestorStatus.Conditions, cond)
		}

		if reflect.DeepEqual(fresh.Status, policyCopy.Status) {
			return nil
		}
		_, err = c.gateway.client.ExperimentalV1alpha1().XTelemetryPolicies(policy.Namespace).UpdateStatus(ctx, policyCopy, metav1.UpdateOptions{})
		return err
	})
}

// hasTelemetryPoliciesTargetingGateway returns true if any XTelemetryPolicy has a
// targetRef to the given Gateway. Used to block Gateway finalizer removal until
// all targeting telemetry policies are removed (avoids dangling refs).
func hasTelemetryPoliciesTargetingGateway(c *Controller, gw *gatewayv1.Gateway) bool {
	policies, err := c.gateway.xTelemetryPolicyLister.XTelemetryPolicies(gw.Namespace).List(labels.Everything())
	if err != nil {
		klog.V(4).ErrorS(err, "failed to list XTelemetryPolicies for Gateway finalizer")
		return true // conservatively block
	}
	for _, policy := range policies {
		for _, targetRef := range policy.Spec.TargetRefs {
			if isTelemetryGatewayTargetRef(targetRef) && string(targetRef.Name) == gw.Name {
				return true
			}
		}
	}
	return false
}
