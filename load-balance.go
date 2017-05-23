package loadbalanceManager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	// "cloud.google.com/go/compute/metadata"
	"google.golang.org/api/compute/v1"
)

type LoadBalanceTools struct {
	client *http.Client
	// compute client
	service *compute.Service

	ctx context.Context

	ProjectID string

	GetBackendService func(name string) (*compute.BackendService, error)

	GetUrlMap func(name string) (*compute.UrlMap, error)

	GetTargetHttpProxy func(name string) (*compute.TargetHttpProxy, error)

	GetTargetHttpsProxy func(name string) (*compute.TargetHttpsProxy, error)

	GetGlobalAddress func(name string) (*compute.Address, error)

	GetForwardRule func(name string) (*compute.ForwardingRule, error)

	GetSslCertificate func(name string) (*compute.SslCertificate, error)

	InsertUrlMap func(name string, defaultService string) (*compute.Operation, error)

	InsertTargetHttpProxy func(name string, urlMap string) (*compute.Operation, error)

	InsertTargetHttpsProxy func(name string, urlMap string, sslCert []string) (*compute.Operation, error)

	InsertTcpGlobalForwardRule func(name string, ipAddress string, targetProxy string, portRange string) (*compute.Operation, error)

	InsertGlobalAddress func(name string) (*compute.Operation, error)

	InsertCertificate func(name string, certificate string, privateKey string) (*compute.Operation, error)

	SetTargetHttpsProxySslCert func(name string, sslCert []string) (*compute.Operation, error)

	DeleteSslCertificate func(name string) (*compute.Operation, error)

	// ResouceIsReady func(name string) bool
}

func NewLoadBalanceTools(projectID string) (r *LoadBalanceTools, err error) {
	googleClient, err := GoogleClient(compute.CloudPlatformScope, compute.ComputeScope)
	if err != nil {
		log.Fatalln(err)
	}
	newService, err := compute.New(googleClient)
	if err != nil {
		log.Fatalln(err)
	}
	newCtx := context.Background()
	r = &LoadBalanceTools{
		service:   newService,
		ProjectID: projectID,
		ctx:       newCtx,
		client:    googleClient,
	}
	r.GetBackendService = r.getBackendService
	r.GetUrlMap = r.getUrlMap
	r.GetGlobalAddress = r.getGlobalAddress
	r.GetTargetHttpProxy = r.getTargetHttpProxy
	r.GetTargetHttpsProxy = r.getTargetHttpsProxy
	r.GetForwardRule = r.getForwardRule
	r.GetSslCertificate = r.getSslCertificate
	r.InsertUrlMap = r.insertUrlMap
	r.InsertTargetHttpProxy = r.insertTargetHttpProxy
	r.InsertTargetHttpsProxy = r.insertTargetHttpsProxy
	r.InsertTcpGlobalForwardRule = r.insertTcpGobalForwardingRule
	r.InsertGlobalAddress = r.insertGlobalAddress
	r.InsertCertificate = r.insertCertificate
	r.SetTargetHttpsProxySslCert = r.setTargetHttpsProxySslCert
	r.DeleteSslCertificate = r.deleteCertificate
	// r.ResouceIsReady = r.resourceIsReady
	return
}

// GetBackendService ...
func (s *LoadBalanceTools) getBackendService(name string) (*compute.BackendService, error) {
	resp, err := s.service.BackendServices.Get(s.ProjectID, name).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *LoadBalanceTools) getUrlMap(name string) (*compute.UrlMap, error) {
	resp, err := s.service.UrlMaps.Get(s.ProjectID, name).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *LoadBalanceTools) getGlobalAddress(name string) (*compute.Address, error) {
	resp, err := s.service.GlobalAddresses.Get(s.ProjectID, name).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *LoadBalanceTools) getTargetHttpProxy(name string) (*compute.TargetHttpProxy, error) {
	resp, err := s.service.TargetHttpProxies.Get(s.ProjectID, name).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *LoadBalanceTools) getTargetHttpsProxy(name string) (*compute.TargetHttpsProxy, error) {
	resp, err := s.service.TargetHttpsProxies.Get(s.ProjectID, name).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *LoadBalanceTools) getForwardRule(name string) (*compute.ForwardingRule, error) {
	resp, err := s.service.GlobalForwardingRules.Get(s.ProjectID, name).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp, nil

}

func (s *LoadBalanceTools) getSslCertificate(name string) (*compute.SslCertificate, error) {
	resp, err := s.service.SslCertificates.Get(s.ProjectID, name).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *LoadBalanceTools) insertUrlMap(name string, defaultService string) (*compute.Operation, error) {
	resp, err := s.service.UrlMaps.Insert(s.ProjectID, &compute.UrlMap{
		Name:              name,
		DefaultService:    defaultService,
		Kind:              "compute#urlMap",
		CreationTimestamp: time.Now().Format(time.RFC3339),
	}).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return s.resourceIsReady(resp)
}

func (s *LoadBalanceTools) insertTargetHttpProxy(name string, urlMap string) (*compute.Operation, error) {
	resp, err := s.service.TargetHttpProxies.Insert(s.ProjectID, &compute.TargetHttpProxy{
		Name:              name,
		UrlMap:            urlMap,
		Kind:              "compute#targetHttpProxy",
		CreationTimestamp: time.Now().Format(time.RFC3339),
	}).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return s.resourceIsReady(resp)
}

func (s *LoadBalanceTools) insertTargetHttpsProxy(name string, urlMap string, sslCert []string) (*compute.Operation, error) {
	resp, err := s.service.TargetHttpsProxies.Insert(s.ProjectID, &compute.TargetHttpsProxy{
		Name:              name,
		UrlMap:            urlMap,
		SslCertificates:   sslCert,
		Kind:              "compute#targetHttpsProxy",
		CreationTimestamp: time.Now().Format(time.RFC3339),
	}).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return s.resourceIsReady(resp)
}

func (s *LoadBalanceTools) insertTcpGobalForwardingRule(name string, ipAddress string, targetProxy string, portRange string) (*compute.Operation, error) {
	resp, err := s.service.GlobalForwardingRules.Insert(s.ProjectID, &compute.ForwardingRule{
		Name:              name,
		IPAddress:         ipAddress,
		Target:            targetProxy,
		PortRange:         portRange,
		IPProtocol:        "TCP",
		Kind:              "compute#forwardingRule",
		CreationTimestamp: time.Now().Format(time.RFC3339),
	}).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return s.resourceIsReady(resp)
}

func (s *LoadBalanceTools) insertGlobalAddress(name string) (*compute.Operation, error) {
	resp, err := s.service.GlobalAddresses.Insert(s.ProjectID, &compute.Address{
		Name:              name,
		Kind:              "compute#address",
		CreationTimestamp: time.Now().Format(time.RFC3339),
	}).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return s.resourceIsReady(resp)
}

func (s *LoadBalanceTools) insertCertificate(name string, certificate string, privateKey string) (*compute.Operation, error) {
	resp, err := s.service.SslCertificates.Insert(s.ProjectID, &compute.SslCertificate{
		Name:              name,
		Certificate:       certificate,
		PrivateKey:        privateKey,
		Kind:              "compute#sslCertificate",
		CreationTimestamp: time.Now().Format(time.RFC3339),
	}).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return s.resourceIsReady(resp)
}

func (s *LoadBalanceTools) setTargetHttpsProxySslCert(name string, sslCert []string) (*compute.Operation, error) {
	resp, err := s.service.TargetHttpsProxies.SetSslCertificates(s.ProjectID, name, &compute.TargetHttpsProxiesSetSslCertificatesRequest{
		SslCertificates: sslCert,
	}).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return s.resourceIsReady(resp)
}

func (s *LoadBalanceTools) deleteCertificate(name string) (*compute.Operation, error) {
	resp, err := s.service.SslCertificates.Delete(s.ProjectID, name).Context(s.ctx).Do()
	if err != nil {
		return nil, err
	}
	return s.resourceIsReady(resp)
}

func (s *LoadBalanceTools) resourceIsReady(op *compute.Operation) (*compute.Operation, error) {
	resp, err := s.client.Get(op.SelfLink)
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	err = json.Unmarshal(buf.Bytes(), &op)
	if err != nil {
		return op, err
	}
	for {
		log.Println("Polling", op.Name)
		if op.Status == "DONE" {
			return op, nil
		}
		time.Sleep(time.Second)
		resp, err := s.client.Get(op.SelfLink)
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		err = json.Unmarshal(buf.Bytes(), &op)
		if err != nil {
			return op, err
		}
	}
}

func GoogleClient(scope ...string) (*http.Client, error) {
	keyPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if len(keyPath) < 0 {
		return nil, fmt.Errorf("ENV GOOGLE_APPLICATION_CREDENTIALS not setting")
	}
	jsonKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("[googleClent] %v", err)
	}
	conf, err := google.JWTConfigFromJSON(
		jsonKey,
		scope...,
	)
	if err != nil {
		return nil, fmt.Errorf("[googleClent] %v", err)
	}
	return conf.Client(oauth2.NoContext), nil
}
