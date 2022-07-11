package k8s

import (
	syserrors "errors"
	"fmt"

	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"

	"github.com/banzaicloud/k8s-objectmatcher/patch"

	appsv1 "k8s.io/api/apps/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
)

var log = logf.Log.WithName("k8s-utils")

// ToObjectMeta returns an ObjectMeta based on the given NamespacedName.
func ToObjectMeta(namespacedName types.NamespacedName) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Namespace: namespacedName.Namespace,
		Name:      namespacedName.Name,
	}
}

// ExtractNamespacedName returns an NamespacedName based on the given Object.
func ExtractNamespacedName(object metav1.Object) types.NamespacedName {
	return types.NamespacedName{
		Namespace: object.GetNamespace(),
		Name:      object.GetName(),
	}
}

// IsPodReady checks if both conditions ContainersReady and PodReady of a Pod are true.
func IsPodReady(pod corev1.Pod) bool {
	conditionsTrue := 0
	for _, cond := range pod.Status.Conditions {
		if cond.Status == corev1.ConditionTrue && (cond.Type == corev1.ContainersReady || cond.Type == corev1.PodReady) {
			conditionsTrue++
		}
	}
	return conditionsTrue == 2
}

// PodsByName returns a map of pod names to pods
func PodsByName(pods []corev1.Pod) map[string]corev1.Pod {
	podMap := make(map[string]corev1.Pod, len(pods))
	for _, pod := range pods {
		podMap[pod.Name] = pod
	}
	return podMap
}

// PodNames returns the names of the given pods.
func PodNames(pods []corev1.Pod) []string {
	names := make([]string, 0, len(pods))
	for _, pod := range pods {
		names = append(names, pod.Name)
	}
	return names
}

// GetServiceDNSName returns the fully qualified DNS name for a service
func GetServiceDNSName(svc corev1.Service) []string {
	return []string{
		fmt.Sprintf("%s.%s.svc", svc.Name, svc.Namespace),
		fmt.Sprintf("%s.%s", svc.Name, svc.Namespace),
	}
}

// EmitErrorEvent emits an event if the error is report-worthy
func EmitErrorEvent(r record.EventRecorder, err error, obj runtime.Object, reason, message string, args ...interface{}) {
	// ignore nil errors and conflict issues
	if err == nil || errors.IsConflict(err) {
		return
	}

	r.Eventf(obj, corev1.EventTypeWarning, reason, message, args...)
}

func IsDeploymentReady(deployObj *appsv1.Deployment, expectedReplicas int) bool {

	totalReplicas := int(deployObj.Status.Replicas)
	readyReplicas := int(deployObj.Status.ReadyReplicas)

	condOne := totalReplicas == readyReplicas
	condTwo := readyReplicas == expectedReplicas

	return condOne && condTwo

}

func CheckForK8sObjectUpdate(objectName string, found, desired runtime.Object) (bool, error) {
	reqLogger := log.WithValues("Checking For k8s object update", "Checking For k8s object update")

	objectsMatcher, err := patch.DefaultPatchMaker.Calculate(found, desired, patch.IgnoreStatusFields())
	if err != nil {
		reqLogger.Error(err, "Unable to Calculate diff", err)
		return false, err
	}
	if objectsMatcher == nil {
		reqLogger.Error(err, "Unable to Calculate diff", err)
		return false, syserrors.New("objectsMatcher == nil")
	}
	upgrade := false
	if !objectsMatcher.IsEmpty() {
		upgrade = true
		err = patch.DefaultAnnotator.SetLastAppliedAnnotation(desired)
		if err != nil {
			reqLogger.Error(err, "Unable to set default for k8s-objectmatcher", err)
			return false, err
		}
	}

	reqLogger.Info(fmt.Sprintf("Checking for %s Upgrade", objectName),
		"PATCH", string(objectsMatcher.Patch),
		"upgrade bool", upgrade)

	return upgrade, nil
}

func CompareByHash(a, b interface{}) (bool, error) {

	aMd5, err := extra.GenerateMD5ForSpec(a)
	if err != nil {
		return false, err
	}
	bMd5, err := extra.GenerateMD5ForSpec(b)
	if err != nil {
		return false, err
	}
	if aMd5 == bMd5 {
		return true, nil
	}
	return false, nil
}
