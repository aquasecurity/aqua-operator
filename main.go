/*
Copyright 2022.

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

package main

import (
	"flag"
	"fmt"
	"github.com/aquasecurity/aqua-operator/controllers/aquasecurity/aquastarboard"
	"github.com/aquasecurity/aqua-operator/controllers/ocp"
	"github.com/aquasecurity/aqua-operator/controllers/operator/aquacloudconnector"
	"github.com/aquasecurity/aqua-operator/controllers/operator/aquacsp"
	"github.com/aquasecurity/aqua-operator/controllers/operator/aquadatabase"
	"github.com/aquasecurity/aqua-operator/controllers/operator/aquaenforcer"
	"github.com/aquasecurity/aqua-operator/controllers/operator/aquagateway"
	"github.com/aquasecurity/aqua-operator/controllers/operator/aquakubeenforcer"
	"github.com/aquasecurity/aqua-operator/controllers/operator/aqualightning"
	"github.com/aquasecurity/aqua-operator/controllers/operator/aquascanner"
	"github.com/aquasecurity/aqua-operator/controllers/operator/aquaserver"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	version2 "github.com/aquasecurity/aqua-operator/pkg/version"
	routev1 "github.com/openshift/api/route/v1"
	"os"

	uzap "go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	"runtime"

	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	aquasecurityv1alpha1 "github.com/aquasecurity/aqua-operator/apis/aquasecurity/v1alpha1"
	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
)

var (
	scheme   = k8sRuntime.NewScheme()
	setupLog = logf.Log.WithName("setup")
)

func printVersion() {
	setupLog.Info(fmt.Sprintf("Operator Version: %s", version2.Version))
	setupLog.Info(fmt.Sprintf("Go Version: %s", runtime.Version()))
	setupLog.Info(fmt.Sprintf("Go OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH))
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(operatorv1alpha1.AddToScheme(scheme))
	utilruntime.Must(aquasecurityv1alpha1.AddToScheme(scheme))

	isOpenshift, _ := ocp.VerifyRouteAPI()
	if isOpenshift {
		utilruntime.Must(routev1.AddToScheme(scheme))
	}
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")

	// Parsing flags
	flag.Parse()

	encoderConfig := uzap.NewProductionEncoderConfig()
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder

	encoder := zapcore.NewConsoleEncoder(encoderConfig)
	logf.SetLogger(zap.New(
		zap.Encoder(encoder),
		zap.Level(zapcore.InfoLevel),
		zap.StacktraceLevel(zapcore.PanicLevel),
	),
	)
	printVersion()

	watchNamespace := extra.GetCurrentNameSpace()
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "aqua-operator-lock",
		Namespace:              watchNamespace,
	})

	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&aquacsp.AquaCspReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AquaCsp")
		os.Exit(1)
	}
	if err = (&aquadatabase.AquaDatabaseReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AquaDatabase")
		os.Exit(1)
	}
	if err = (&aquaenforcer.AquaEnforcerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AquaEnforcer")
		os.Exit(1)
	}
	if err = (&aquagateway.AquaGatewayReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AquaGateway")
		os.Exit(1)
	}
	if err = (&aquakubeenforcer.AquaKubeEnforcerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Certs:  aquakubeenforcer.GetKECerts(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AquaKubeEnforcer")
		os.Exit(1)
	}
	if err = (&aquascanner.AquaScannerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AquaScanner")
		os.Exit(1)
	}
	if err = (&aquacloudconnector.AquaCloudConnectorReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AquaCloudConnector")
		os.Exit(1)
	}

	if err = (&aqualightning.AquaLightningReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Certs:  aqualightning.GetKECerts(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AquaKubeEnforcer")
		os.Exit(1)
	}

	if err = (&aquaserver.AquaServerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AquaServer")
		os.Exit(1)
	}
	if err = (&aquastarboard.AquaStarboardReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AquaStarboard")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

//func printVersion() {
//	setupLog.Info(fmt.Sprintf("Operator Version: %s", version.Version))
//	setupLog.Info(fmt.Sprintf("Go Version: %s", k8sRuntime.Version()))
//	setupLog.Info(fmt.Sprintf("Go OS/Arch: %s/%s", k8sRuntime.GOOS, k8sRuntime.GOARCH))
//	setupLog.Info(fmt.Sprintf("Version of operator-sdk: %v", sdkVersion.Version))
//}
