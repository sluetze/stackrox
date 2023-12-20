package k8sutil

import (
	"context"

	"github.com/pkg/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// GetAnyNodeLabels returns the labels of an arbitrary node. This is useful
// to extract global labels such as the cluster name.
func GetAnyNodeLabels(ctx context.Context, client *kubernetes.Clientset) (map[string]string, error) {
	nodeList, err := client.CoreV1().Nodes().List(ctx, v1.ListOptions{Limit: 1})
	if err != nil || nodeList.Size() == 0 {
		return nil, errors.Wrap(err, "listing nodes")
	}
	if nodeList.Size() == 0 {
		return nil, errors.Wrap(err, "no nodes found")
	}
	return nodeList.Items[0].GetLabels(), nil
}
